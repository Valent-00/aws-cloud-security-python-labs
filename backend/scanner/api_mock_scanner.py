"""
api_mock_scanner.py  —  v2.0
==============================
IAM Security Posture Scanner  |  Expanded Detection Coverage

What's new in v2.0
-------------------
  DETECTION
    ✦ Severity bands        — Critical / High / Medium / Low / Info
    ✦ Alert deduplication   — fingerprint-based, only NEW state changes fire
    ✦ Field-level baseline  — catches MFA flip, role change, key-age jump
    ✦ Dormant admin         — admin with no login > DORMANT_ADMIN_DAYS
    ✦ Role escalation       — role promoted between baseline and now
    ✦ Stale account         — any user inactive > STALE_ACCOUNT_DAYS
    ✦ Multiple active keys  — user holds > MAX_ACTIVE_KEYS_PER_USER keys
    ✦ Never-used key        — key exists but has never been used
    ✦ Disabled account      — account disabled but key still active
    ✦ No password rotation  — password older than PASSWORD_MAX_AGE_DAYS
    ✦ Wildcard permission   — IAM policy contains '*:*' or 'Action: *'
    ✦ Root account used     — root login detected (always Critical)
    ✦ Brute force indicator — failed_logins > BRUTE_FORCE_THRESHOLD
    ✦ Off-hours login       — login outside business hours window
    ✦ Geo anomaly           — login country not in user's known countries

  CODE QUALITY
    ✦ Severity enum         — typed, not magic strings
    ✦ Dataclass for Finding — structured, not raw dict
    ✦ Severity-to-SLA map   — response time targets per band
    ✦ Summary table         — printed to console after every scan

Architecture
------------
  fetch_cloud_inventory()         → raw UserRecord list (mock, swap for SDK)
  load_baseline() / save_baseline() → atomic JSON state on disk
  run_all_checks()                → dispatches every detector, deduplicates
  ├── check_mfa_disabled()
  ├── check_stale_key()
  ├── check_never_used_key()
  ├── check_multiple_keys()
  ├── check_no_password_rotation()
  ├── check_dormant_admin()
  ├── check_stale_account()
  ├── check_disabled_account_with_key()
  ├── check_wildcard_permission()
  ├── check_root_account_used()
  ├── check_brute_force()
  ├── check_off_hours_login()
  ├── check_geo_anomaly()
  └── detect_field_level_drift()  → MFA flip, role escalation, key-age jump
  generate_ai_summary()           → Ollama LLM executive report
  export_findings_json()          → machine-readable output for SIEM
  save_report_to_disk()           → per-user audit text file
  run_scanner()                   → full orchestration pipeline

Security Notes
--------------
  * Prompt injection mitigation on all user-controlled fields.
  * Atomic writes (temp-file rename) for baseline and JSON exports.
  * Alert deduplication via SHA-256 fingerprint stored in alert_state.json.
  * All config from environment variables — no secrets in source.

Usage
-----
  python api_mock_scanner.py

  .env keys (all optional, defaults shown):
      OLLAMA_BASE_URL           http://localhost:11434
      OLLAMA_MODEL              llama3.2
      OLLAMA_TIMEOUT_SEC        45
      KEY_ROTATION_DAYS         90
      PASSWORD_MAX_AGE_DAYS     90
      STALE_ACCOUNT_DAYS        60
      DORMANT_ADMIN_DAYS        30
      MAX_ACTIVE_KEYS_PER_USER  1
      BRUTE_FORCE_THRESHOLD     10
      BUSINESS_HOURS_START      8
      BUSINESS_HOURS_END        18
"""

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
import json
import logging
import os
import re
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Third-party
# ---------------------------------------------------------------------------
import requests
from dotenv import load_dotenv

# ===========================================================================
# 1. Bootstrap — env, logging
# ===========================================================================
load_dotenv()

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH: str = os.path.join(SCRIPT_DIR, "scanner_operations.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("iam_scanner")

# ===========================================================================
# 2. Configuration — all from environment, safe defaults
# ===========================================================================
OLLAMA_BASE_URL: str          = os.getenv("OLLAMA_BASE_URL",     "http://localhost:11434")
OLLAMA_MODEL: str             = os.getenv("OLLAMA_MODEL",        "llama3.2")
OLLAMA_TIMEOUT_SEC: int       = int(os.getenv("OLLAMA_TIMEOUT_SEC",        "45"))
KEY_ROTATION_LIMIT_DAYS: int  = int(os.getenv("KEY_ROTATION_DAYS",         "90"))
PASSWORD_MAX_AGE_DAYS: int    = int(os.getenv("PASSWORD_MAX_AGE_DAYS",      "90"))
STALE_ACCOUNT_DAYS: int       = int(os.getenv("STALE_ACCOUNT_DAYS",         "60"))
DORMANT_ADMIN_DAYS: int       = int(os.getenv("DORMANT_ADMIN_DAYS",         "30"))
MAX_ACTIVE_KEYS_PER_USER: int = int(os.getenv("MAX_ACTIVE_KEYS_PER_USER",    "1"))
BRUTE_FORCE_THRESHOLD: int    = int(os.getenv("BRUTE_FORCE_THRESHOLD",       "10"))
BUSINESS_HOURS_START: int     = int(os.getenv("BUSINESS_HOURS_START",         "8"))
BUSINESS_HOURS_END: int       = int(os.getenv("BUSINESS_HOURS_END",          "18"))

STATE_DIR: str         = os.path.join(SCRIPT_DIR, "state")
STATE_FILE_PATH: str   = os.path.join(STATE_DIR, "baseline_iam.json")
ALERT_STATE_PATH: str  = os.path.join(STATE_DIR, "alert_state.json")
REPORTS_DIR: str       = os.path.join(SCRIPT_DIR, "reports")

# ===========================================================================
# 3. Severity system
# ===========================================================================

class Severity(str, Enum):
    """
    Five-band severity classification, matching industry standards
    (ISO 27001, NIST SP 800-61, SOC 2).

    Stored as a string so it serialises cleanly to JSON without
    needing a custom encoder.
    """
    CRITICAL = "Critical"   # Respond within 1 hour
    HIGH     = "High"       # Respond within 4 hours
    MEDIUM   = "Medium"     # Respond within 24 hours
    LOW      = "Low"        # Respond within 72 hours
    INFO     = "Info"       # Informational, no SLA


# Response-time SLA targets per severity band (for report display)
SEVERITY_SLA: dict[Severity, str] = {
    Severity.CRITICAL: "Respond within 1 hour",
    Severity.HIGH:     "Respond within 4 hours",
    Severity.MEDIUM:   "Respond within 24 hours",
    Severity.LOW:      "Respond within 72 hours",
    Severity.INFO:     "No SLA — informational only",
}

# Numeric risk score ranges per band
SEVERITY_SCORE_RANGES: dict[Severity, tuple[int, int]] = {
    Severity.CRITICAL: (90, 99),
    Severity.HIGH:     (70, 89),
    Severity.MEDIUM:   (40, 69),
    Severity.LOW:      (10, 39),
    Severity.INFO:     (0,   9),
}

# Base risk scores per alert type — security leads adjust here, not in logic
RISK_BASE_SCORES: dict[str, int] = {
    # Identity / credential
    "MFA Disabled":                  50,   # Medium
    "Stale Key":                     25,   # Low → escalates with age
    "Never Used Key":                20,   # Low
    "Multiple Active Keys":          35,   # Low-Medium
    "No Password Rotation":          40,   # Medium
    # Account lifecycle
    "New User Created":              40,   # Medium
    "Stale Account":                 30,   # Low
    "Dormant Admin":                 65,   # High
    "Disabled Account With Key":     55,   # Medium-High
    # Privilege & policy
    "Role Escalation":               70,   # High
    "Wildcard Permission":           80,   # High
    # Behavioural
    "Root Account Used":             95,   # Critical (almost always)
    "Brute Force Indicator":         60,   # Medium-High
    "Off-Hours Login":               20,   # Low (contextual)
    "Geo Anomaly":                   65,   # High
    # Drift
    "MFA Disabled (Drift)":          55,   # Medium-High — was enabled, now not
    "Role Changed":                  60,   # High
    "Key Age Jump":                  30,   # Low
}

ADMIN_ROLE_MULTIPLIER: float = 1.5
MAX_RISK_SCORE: int = 99

# Roles considered privileged — escalation to any of these triggers alert
PRIVILEGED_ROLES: set[str] = {"Administrator", "Root", "SuperAdmin", "Owner"}

# ===========================================================================
# 4. Data structures
# ===========================================================================

# Type alias — one IAM user record as returned by fetch_cloud_inventory()
UserRecord = dict[str, Any]


@dataclass
class Finding:
    """
    A single security finding produced by any detector.

    Using a dataclass instead of a raw dict gives:
      - IDE autocomplete / type checking on every field
      - Guaranteed field presence (no KeyError on missing keys)
      - Clean serialisation via asdict()

    Fields
    ------
    username      : The IAM username this finding relates to.
    alert_type    : Short identifier matching a key in RISK_BASE_SCORES.
    severity      : Severity band (Critical / High / Medium / Low / Info).
    risk_score    : Numeric score in [0, 99].
    detail        : Human-readable explanation of why this fired.
    sla           : Response-time target string from SEVERITY_SLA.
    fingerprint   : SHA-256 of (username + alert_type) — used for dedup.
    """
    username:    str
    alert_type:  str
    severity:    Severity
    risk_score:  int
    detail:      str
    sla:         str       = field(init=False)
    fingerprint: str       = field(init=False)

    def __post_init__(self) -> None:
        self.sla         = SEVERITY_SLA[self.severity]
        self.fingerprint = _make_fingerprint(self.username, self.alert_type)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (converts Severity enum to string)."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ===========================================================================
# 5. Helpers
# ===========================================================================

# Prompt injection pattern — strips adversarial content before LLM calls
_PROMPT_INJECTION_PATTERN: re.Pattern[str] = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?"
    r"|<[^>]{0,200}>"
    r"|```"
    r"|\r\n|\r|\n"
    r"|\x00)",
    flags=re.IGNORECASE,
)


def sanitise_for_prompt(value: str) -> str:
    """
    Strip prompt-injection patterns from a user-controlled string before
    interpolating it into an LLM prompt.

    Args:
        value: Raw string from external data (username, role, country, etc.)

    Returns:
        Cleaned string, max 128 characters.
    """
    cleaned: str = _PROMPT_INJECTION_PATTERN.sub(" ", value)
    return cleaned[:128].strip()


def score_to_severity(score: int) -> Severity:
    """
    Map a numeric risk score to the appropriate Severity band.

    Args:
        score: Integer in [0, 99].

    Returns:
        The matching Severity enum value.
    """
    for sev, (lo, hi) in SEVERITY_SCORE_RANGES.items():
        if lo <= score <= hi:
            return sev
    return Severity.INFO


def calculate_risk_score(
    alert_type: str,
    user_role:  str,
    extra:      int = 0,
) -> int:
    """
    Calculate a capped risk score for one alert.

    Rules:
      1. Start from RISK_BASE_SCORES[alert_type] (0 if unknown).
      2. Add `extra` penalty points (used for age-based escalation).
      3. Multiply by ADMIN_ROLE_MULTIPLIER when role is privileged.
      4. Cap at MAX_RISK_SCORE (99).

    Args:
        alert_type : Key from RISK_BASE_SCORES.
        user_role  : The user's IAM role string.
        extra      : Additional penalty points (e.g. days over limit).

    Returns:
        Integer score in [0, 99].
    """
    score: float = RISK_BASE_SCORES.get(alert_type, 0) + extra
    if user_role in PRIVILEGED_ROLES:
        score *= ADMIN_ROLE_MULTIPLIER
    return min(round(score), MAX_RISK_SCORE)


def _make_fingerprint(username: str, alert_type: str) -> str:
    """
    Produce a stable SHA-256 fingerprint for a (username, alert_type) pair.

    This fingerprint is used by the deduplication layer — an alert that has
    already been seen and not yet resolved will not re-fire on the next scan.

    Args:
        username   : IAM username.
        alert_type : Alert type string.

    Returns:
        64-character lowercase hex digest.
    """
    import hashlib
    raw: str = f"{username}::{alert_type}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _make_finding(
    username:   str,
    alert_type: str,
    user_role:  str,
    detail:     str,
    extra:      int = 0,
) -> Finding:
    """
    Convenience factory — calculates score + severity and returns a Finding.

    Args:
        username   : IAM username.
        alert_type : Key from RISK_BASE_SCORES.
        user_role  : User's IAM role (affects multiplier).
        detail     : Human-readable explanation.
        extra      : Extra penalty points (age, count overages, etc.)

    Returns:
        A fully populated Finding dataclass instance.
    """
    score: int      = calculate_risk_score(alert_type, user_role, extra)
    sev:   Severity = score_to_severity(score)
    return Finding(
        username=username,
        alert_type=alert_type,
        severity=sev,
        risk_score=score,
        detail=detail,
    )


# ===========================================================================
# 6. Alert deduplication
# ===========================================================================

def load_alert_state() -> dict[str, str]:
    """
    Load the persisted set of active alert fingerprints from disk.

    Each key is a fingerprint; the value is the ISO timestamp when it
    was first seen. Alerts already in this dict are suppressed on the
    next scan run so the same misconfiguration does not spam the log.

    Returns:
        Dict of {fingerprint: first_seen_timestamp}, or {} on first run.
    """
    if not os.path.exists(ALERT_STATE_PATH):
        return {}
    try:
        with open(ALERT_STATE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load alert state — treating as empty: %s", exc)
        return {}


def save_alert_state(state: dict[str, str]) -> None:
    """
    Atomically persist the active alert fingerprint set to disk.

    Args:
        state: Dict of {fingerprint: first_seen_timestamp}.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=STATE_DIR, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=4)
        os.replace(tmp_path, ALERT_STATE_PATH)
    except OSError:
        os.unlink(tmp_path)
        raise


def deduplicate_findings(
    findings: list[Finding],
    alert_state: dict[str, str],
) -> tuple[list[Finding], dict[str, str]]:
    """
    Filter out findings whose fingerprint is already in alert_state,
    then add new fingerprints to the state.

    This ensures an alert fires ONCE when a misconfiguration is first
    detected, and stays silent on subsequent scans until it is resolved.

    Args:
        findings    : Raw findings from all detectors.
        alert_state : Currently active fingerprints loaded from disk.

    Returns:
        (new_findings, updated_alert_state)
          new_findings        — only the alerts that are genuinely new.
          updated_alert_state — state dict to be saved back to disk.
    """
    now_iso: str = datetime.now(timezone.utc).isoformat()
    new_findings: list[Finding] = []
    updated_state: dict[str, str] = dict(alert_state)  # copy

    for finding in findings:
        fp: str = finding.fingerprint
        if fp not in updated_state:
            new_findings.append(finding)
            updated_state[fp] = now_iso
            logger.info(
                "NEW alert [%s] %s — %s (score %d)",
                finding.severity.value, finding.username,
                finding.alert_type, finding.risk_score,
            )
        else:
            logger.debug(
                "SUPPRESSED duplicate — %s | %s (first seen: %s)",
                finding.username, finding.alert_type, updated_state[fp],
            )

    return new_findings, updated_state


# ===========================================================================
# 7. Baseline management
# ===========================================================================

def load_baseline() -> list[UserRecord] | None:
    """
    Load the saved IAM baseline from disk.

    Returns:
        List of UserRecord dicts, or None if no baseline exists yet.
    """
    if not os.path.exists(STATE_FILE_PATH):
        return None
    try:
        with open(STATE_FILE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to load baseline: %s", exc)
        return None


def save_baseline(data: list[UserRecord]) -> None:
    """
    Atomically persist the current IAM inventory as the new baseline.

    Uses write-to-temp then os.replace() so the baseline is never
    left in a partial state if the process crashes.

    Args:
        data: Current IAM inventory to persist.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=STATE_DIR, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        os.replace(tmp_path, STATE_FILE_PATH)
        logger.info("Baseline saved → %s", STATE_FILE_PATH)
    except OSError:
        os.unlink(tmp_path)
        raise


# ===========================================================================
# 8. Mock inventory — swap this body for your real cloud SDK call
# ===========================================================================

def fetch_cloud_inventory() -> list[UserRecord]:
    """
    Return the current IAM user inventory.

    ARCHITECTURE NOTE
    -----------------
    This is the ONLY function that knows where user data comes from.
    Replace the mock list below with your actual SDK call (boto3, google-cloud-iam,
    azure-identity, etc.) — nothing else in the scanner needs to change.

    UserRecord schema (all fields)
    --------------------------------
    username              str   — unique user identifier
    role                  str   — IAM role (Administrator, Developer, DevOps …)
    mfa_enabled           bool  — is MFA currently active?
    active_key_count      int   — number of currently active API keys
    key_age_days          int   — age of the oldest active key in days
    key_last_used_days    int   — days since the key was last used (-1 = never)
    password_age_days     int   — days since password was last rotated
    last_login_days       int   — days since last successful login (-1 = never)
    account_enabled       bool  — is the account active?
    permissions           list  — list of IAM permission strings
    last_login_hour       int   — UTC hour of the last login (0–23, -1 = never)
    known_countries       list  — countries this user has logged in from before
    last_login_country    str   — country of the most recent login ("" = unknown)
    failed_logins_24h     int   — failed login attempts in the last 24 hours
    is_root               bool  — is this the cloud root/super-admin account?

    Returns:
        List of UserRecord dicts.
    """
    return [
        # ── Scenario 1: Admin with MFA disabled, stale key, dormant
        {
            "username": "admin_root",
            "role": "Administrator",
            "mfa_enabled": False,
            "active_key_count": 2,
            "key_age_days": 115,
            "key_last_used_days": 5,
            "password_age_days": 100,
            "last_login_days": 45,
            "account_enabled": True,
            "permissions": ["s3:*", "ec2:*", "iam:*"],
            "last_login_hour": 14,
            "known_countries": ["Malaysia"],
            "last_login_country": "Malaysia",
            "failed_logins_24h": 0,
            "is_root": False,
        },
        # ── Scenario 2: Intern with MFA off, logins at 2 AM
        {
            "username": "intern_dev01",
            "role": "Developer",
            "mfa_enabled": False,
            "active_key_count": 1,
            "key_age_days": 12,
            "key_last_used_days": -1,
            "password_age_days": 10,
            "last_login_days": 1,
            "account_enabled": True,
            "permissions": ["s3:GetObject", "ec2:DescribeInstances"],
            "last_login_hour": 2,
            "known_countries": ["Malaysia"],
            "last_login_country": "Malaysia",
            "failed_logins_24h": 3,
            "is_root": False,
        },
        # ── Scenario 3: Disabled account still holding an active key
        {
            "username": "stale_deployer",
            "role": "DevOps",
            "mfa_enabled": False,
            "active_key_count": 1,
            "key_age_days": 210,
            "key_last_used_days": -1,
            "password_age_days": 210,
            "last_login_days": 95,
            "account_enabled": False,
            "permissions": ["ec2:*", "s3:*"],
            "last_login_hour": 10,
            "known_countries": ["Malaysia"],
            "last_login_country": "Malaysia",
            "failed_logins_24h": 0,
            "is_root": False,
        },
        # ── Scenario 4: Service account with wildcard permission
        {
            "username": "svc_pipeline",
            "role": "Developer",
            "mfa_enabled": True,
            "active_key_count": 1,
            "key_age_days": 30,
            "key_last_used_days": 1,
            "password_age_days": 30,
            "last_login_days": 0,
            "account_enabled": True,
            "permissions": ["*:*"],
            "last_login_hour": 9,
            "known_countries": ["Malaysia"],
            "last_login_country": "Malaysia",
            "failed_logins_24h": 0,
            "is_root": False,
        },
        # ── Scenario 5: Brute-force target + geo anomaly
        {
            "username": "finance_mgr",
            "role": "Developer",
            "mfa_enabled": True,
            "active_key_count": 1,
            "key_age_days": 20,
            "key_last_used_days": 2,
            "password_age_days": 20,
            "last_login_days": 0,
            "account_enabled": True,
            "permissions": ["s3:GetObject"],
            "last_login_hour": 11,
            "known_countries": ["Malaysia"],
            "last_login_country": "Russia",
            "failed_logins_24h": 15,
            "is_root": False,
        },
        # ── Scenario 6: Root account login (always Critical)
        {
            "username": "root",
            "role": "Root",
            "mfa_enabled": True,
            "active_key_count": 0,
            "key_age_days": 0,
            "key_last_used_days": -1,
            "password_age_days": 365,
            "last_login_days": 1,
            "account_enabled": True,
            "permissions": ["*:*"],
            "last_login_hour": 3,
            "known_countries": ["Malaysia"],
            "last_login_country": "Malaysia",
            "failed_logins_24h": 0,
            "is_root": True,
        },
    ]


# ===========================================================================
# 9. Detectors — one function per check
#    Each returns a list[Finding] (empty = clean, no issue found).
#    All are pure functions: they read user data, return findings, no I/O.
# ===========================================================================

def check_mfa_disabled(user: UserRecord) -> list[Finding]:
    """
    Flag any account that does not have MFA enabled.
    Severity escalates for privileged roles.
    """
    if user.get("mfa_enabled") is True:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="MFA Disabled",
        user_role=user["role"],
        detail=(
            f"MFA is not enabled for '{user['username']}' "
            f"(role: {user['role']}). Account is vulnerable to "
            "credential-stuffing and password spray attacks."
        ),
    )]


def check_stale_key(user: UserRecord) -> list[Finding]:
    """
    Flag API keys older than KEY_ROTATION_LIMIT_DAYS.
    Penalty increases by 1 point per day over the limit.
    """
    age: int = user.get("key_age_days", 0)
    if age <= KEY_ROTATION_LIMIT_DAYS:
        return []
    overage: int = age - KEY_ROTATION_LIMIT_DAYS
    return [_make_finding(
        username=user["username"],
        alert_type="Stale Key",
        user_role=user["role"],
        detail=(
            f"API key for '{user['username']}' is {age} days old "
            f"({overage} days past the {KEY_ROTATION_LIMIT_DAYS}-day rotation limit). "
            "Stale keys are a common initial access vector."
        ),
        extra=overage,
    )]


def check_never_used_key(user: UserRecord) -> list[Finding]:
    """
    Flag keys that have never been used (key_last_used_days == -1).
    A key that was created but never used is an orphaned attack surface.
    """
    if user.get("key_last_used_days", 0) != -1:
        return []
    if user.get("active_key_count", 0) == 0:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Never Used Key",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' has an active API key that has never been used. "
            "Unused keys should be deleted to reduce attack surface."
        ),
    )]


def check_multiple_keys(user: UserRecord) -> list[Finding]:
    """
    Flag users holding more than MAX_ACTIVE_KEYS_PER_USER active keys.
    Each extra key is an independent credential that can be leaked.
    """
    count: int = user.get("active_key_count", 0)
    if count <= MAX_ACTIVE_KEYS_PER_USER:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Multiple Active Keys",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' holds {count} active API keys "
            f"(limit: {MAX_ACTIVE_KEYS_PER_USER}). Each key is an independent "
            "attack surface and increases the blast radius of a credential leak."
        ),
    )]


def check_no_password_rotation(user: UserRecord) -> list[Finding]:
    """
    Flag passwords older than PASSWORD_MAX_AGE_DAYS.
    """
    age: int = user.get("password_age_days", 0)
    if age <= PASSWORD_MAX_AGE_DAYS:
        return []
    overage: int = age - PASSWORD_MAX_AGE_DAYS
    return [_make_finding(
        username=user["username"],
        alert_type="No Password Rotation",
        user_role=user["role"],
        detail=(
            f"Password for '{user['username']}' is {age} days old "
            f"({overage} days past the {PASSWORD_MAX_AGE_DAYS}-day rotation policy). "
            "Stale passwords increase exposure window after a credential breach."
        ),
        extra=min(overage // 10, 20),  # +1 score per 10 days over, max +20
    )]


def check_dormant_admin(user: UserRecord) -> list[Finding]:
    """
    Flag privileged-role accounts with no login in DORMANT_ADMIN_DAYS.
    A dormant admin account is a prime target for takeover — it has
    elevated permissions but may not be actively monitored.
    """
    if user["role"] not in PRIVILEGED_ROLES:
        return []
    last_login: int = user.get("last_login_days", -1)
    if last_login == -1 or last_login <= DORMANT_ADMIN_DAYS:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Dormant Admin",
        user_role=user["role"],
        detail=(
            f"Administrator '{user['username']}' has not logged in for "
            f"{last_login} days (threshold: {DORMANT_ADMIN_DAYS} days). "
            "Dormant admin accounts are high-value targets for lateral movement."
        ),
    )]


def check_stale_account(user: UserRecord) -> list[Finding]:
    """
    Flag any active account with no login in STALE_ACCOUNT_DAYS.
    Applies to all roles — dormant admin is a separate, higher-severity check.
    """
    if not user.get("account_enabled", True):
        return []  # disabled accounts handled by check_disabled_account_with_key
    last_login: int = user.get("last_login_days", -1)
    if last_login == -1 or last_login <= STALE_ACCOUNT_DAYS:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Stale Account",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' has not logged in for {last_login} days "
            f"(threshold: {STALE_ACCOUNT_DAYS} days). "
            "Consider disabling or deprovisioning this account."
        ),
    )]


def check_disabled_account_with_key(user: UserRecord) -> list[Finding]:
    """
    Flag accounts that are disabled but still possess active API keys.
    A disabled account with a live key can still authenticate via the API —
    the key bypasses the account-disabled control entirely.
    """
    if user.get("account_enabled", True):
        return []
    if user.get("active_key_count", 0) == 0:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Disabled Account With Key",
        user_role=user["role"],
        detail=(
            f"Account '{user['username']}' is disabled but still has "
            f"{user['active_key_count']} active API key(s). "
            "Disabling an account does NOT revoke API keys — they must be deleted separately."
        ),
    )]


def check_wildcard_permission(user: UserRecord) -> list[Finding]:
    """
    Flag users whose permission list contains a wildcard ('*:*' or 'Action: *').
    Wildcard permissions violate least-privilege and are an instant privilege
    escalation path for any attacker who compromises this account.
    """
    perms: list[str] = user.get("permissions", [])
    wildcards: list[str] = [p for p in perms if "*" in p]
    if not wildcards:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Wildcard Permission",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' has wildcard permission(s): {wildcards}. "
            "This violates the Principle of Least Privilege. "
            "Replace with specific, scoped permission statements."
        ),
    )]


def check_root_account_used(user: UserRecord) -> list[Finding]:
    """
    Flag any login by the cloud root / super-admin account.
    Best practice (AWS, GCP, Azure) is that root is NEVER used for
    day-to-day operations — only for initial setup or account recovery.
    Any recent login is an immediate Critical alert.
    """
    if not user.get("is_root", False):
        return []
    last_login: int = user.get("last_login_days", -1)
    if last_login == -1 or last_login > 7:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Root Account Used",
        user_role=user["role"],
        detail=(
            f"Root account '{user['username']}' logged in {last_login} day(s) ago. "
            "Root accounts should NEVER be used for regular operations. "
            "Investigate immediately and enforce root login restriction."
        ),
    )]


def check_brute_force(user: UserRecord) -> list[Finding]:
    """
    Flag accounts with failed login attempts above BRUTE_FORCE_THRESHOLD
    in the last 24 hours. This is a strong indicator of an ongoing
    credential attack against this specific account.
    """
    failed: int = user.get("failed_logins_24h", 0)
    if failed <= BRUTE_FORCE_THRESHOLD:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Brute Force Indicator",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' had {failed} failed login attempts in the "
            f"last 24 hours (threshold: {BRUTE_FORCE_THRESHOLD}). "
            "This pattern is consistent with a brute-force or credential-stuffing attack."
        ),
    )]


def check_off_hours_login(user: UserRecord) -> list[Finding]:
    """
    Flag logins that occurred outside business hours (BUSINESS_HOURS_START–END UTC).
    Off-hours logins are not inherently malicious but are a contextual
    indicator worth surfacing, especially for privileged accounts.
    """
    hour: int = user.get("last_login_hour", -1)
    if hour == -1:
        return []
    if BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Off-Hours Login",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' last logged in at {hour:02d}:00 UTC, "
            f"outside business hours ({BUSINESS_HOURS_START:02d}:00–{BUSINESS_HOURS_END:02d}:00 UTC). "
            "Correlate with other alerts before escalating."
        ),
    )]


def check_geo_anomaly(user: UserRecord) -> list[Finding]:
    """
    Flag logins from countries outside a user's known/baseline set.
    A login from a new geography is a strong indicator of account compromise,
    particularly when combined with MFA disabled or brute-force activity.
    """
    last_country: str  = user.get("last_login_country", "")
    known: list[str]   = user.get("known_countries", [])
    if not last_country or not known:
        return []
    if last_country in known:
        return []
    return [_make_finding(
        username=user["username"],
        alert_type="Geo Anomaly",
        user_role=user["role"],
        detail=(
            f"'{user['username']}' logged in from '{last_country}', "
            f"which is not in their known countries: {known}. "
            "This may indicate account compromise or an unauthorised login."
        ),
    )]


# ===========================================================================
# 10. Field-level drift detector
#     Compares every field of every user against the baseline.
#     Catches: MFA flipped off, role escalated, key age jumped.
# ===========================================================================

def detect_field_level_drift(
    current_data:  list[UserRecord],
    baseline_data: list[UserRecord],
) -> list[Finding]:
    """
    Compare the current IAM snapshot against the baseline field-by-field.

    Catches:
      - New user accounts (username not in baseline)
      - MFA that was True in baseline but is now False
      - Role that changed to a higher-privilege role
      - Key age that jumped (key replaced but also not rotated in time)
      - Baseline role change to any different role

    Args:
        current_data:  Current live inventory.
        baseline_data: Previously saved baseline.

    Returns:
        List of drift-based Findings.
    """
    baseline_map: dict[str, UserRecord] = {
        u["username"]: u for u in baseline_data
    }
    findings: list[Finding] = []

    for user in current_data:
        uname:    str = user["username"]
        role:     str = user["role"]
        baseline: UserRecord | None = baseline_map.get(uname)

        # ── New user not in baseline ──────────────────────────────────────
        if baseline is None:
            findings.append(_make_finding(
                username=uname,
                alert_type="New User Created",
                user_role=role,
                detail=(
                    f"User '{uname}' (role: {role}) was not present in the "
                    "baseline snapshot. Verify this account creation was authorised."
                ),
            ))
            logger.warning("Drift: new user detected — %s (%s)", uname, role)
            continue

        # ── MFA flipped from True → False ─────────────────────────────────
        if baseline.get("mfa_enabled") is True and user.get("mfa_enabled") is False:
            findings.append(_make_finding(
                username=uname,
                alert_type="MFA Disabled (Drift)",
                user_role=role,
                detail=(
                    f"MFA for '{uname}' was ENABLED in the last baseline but is "
                    "now DISABLED. This is a state regression — investigate who "
                    "disabled it and why."
                ),
            ))
            logger.warning("Drift: MFA disabled since baseline — %s", uname)

        # ── Role escalated to a privileged role ───────────────────────────
        old_role: str = baseline.get("role", "")
        if old_role != role and role in PRIVILEGED_ROLES and old_role not in PRIVILEGED_ROLES:
            findings.append(_make_finding(
                username=uname,
                alert_type="Role Escalation",
                user_role=role,
                detail=(
                    f"'{uname}' was promoted from '{old_role}' to '{role}' since "
                    "the last baseline. Privilege escalation must be reviewed and "
                    "approved by an authorised administrator."
                ),
            ))
            logger.warning("Drift: role escalation — %s: %s → %s", uname, old_role, role)

        # ── Any role change (not necessarily escalation) ──────────────────
        elif old_role != role:
            findings.append(_make_finding(
                username=uname,
                alert_type="Role Changed",
                user_role=role,
                detail=(
                    f"'{uname}' role changed from '{old_role}' to '{role}' "
                    "since the last baseline. Confirm this change was authorised."
                ),
            ))
            logger.warning("Drift: role changed — %s: %s → %s", uname, old_role, role)

        # ── Key age jumped (new key issued but already approaching limit) ──
        old_age: int = baseline.get("key_age_days", 0)
        new_age: int = user.get("key_age_days", 0)
        if new_age > old_age + 30 and new_age > KEY_ROTATION_LIMIT_DAYS * 0.75:
            findings.append(_make_finding(
                username=uname,
                alert_type="Key Age Jump",
                user_role=role,
                detail=(
                    f"'{uname}' key age jumped from {old_age} to {new_age} days. "
                    "This suggests a new key was issued but is already approaching "
                    "the rotation limit."
                ),
            ))

    return findings


# ===========================================================================
# 11. Master scanner — runs all checks across all users
# ===========================================================================

# Registry of all per-user detector functions.
# To add a new check: write the function above and add it here — nothing else
# in the codebase needs to change.
_DETECTORS = [
    check_mfa_disabled,
    check_stale_key,
    check_never_used_key,
    check_multiple_keys,
    check_no_password_rotation,
    check_dormant_admin,
    check_stale_account,
    check_disabled_account_with_key,
    check_wildcard_permission,
    check_root_account_used,
    check_brute_force,
    check_off_hours_login,
    check_geo_anomaly,
]


def run_all_checks(
    current_data:  list[UserRecord],
    baseline_data: list[UserRecord],
    alert_state:   dict[str, str],
) -> tuple[list[Finding], dict[str, str]]:
    """
    Run every registered detector across every user, then deduplicate.

    Steps:
      1. Run detect_field_level_drift() across the full user list.
      2. Run each per-user detector in _DETECTORS for every user.
      3. Deduplicate all combined findings against the active alert state.

    Args:
        current_data:  Live IAM inventory.
        baseline_data: Previously saved baseline (empty list if first run).
        alert_state:   Currently active alert fingerprints.

    Returns:
        (new_findings, updated_alert_state)
    """
    raw_findings: list[Finding] = []

    # Field-level drift (whole-list comparison)
    raw_findings.extend(detect_field_level_drift(current_data, baseline_data))

    # Per-user checks
    for user in current_data:
        for detector in _DETECTORS:
            raw_findings.extend(detector(user))

    logger.info("Raw findings before dedup: %d", len(raw_findings))

    # Deduplicate
    new_findings, updated_state = deduplicate_findings(raw_findings, alert_state)
    return new_findings, updated_state


# ===========================================================================
# 12. Console summary table
# ===========================================================================

def print_summary_table(findings: list[Finding]) -> None:
    """
    Print a formatted summary table to the console after a scan completes.

    Groups findings by severity band and shows counts, so a quick glance
    tells you whether there is a Critical issue requiring immediate action.

    Args:
        findings: All new (deduplicated) findings from this scan run.
    """
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    col_width = 10
    sev_labels = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH:     "HIGH    ",
        Severity.MEDIUM:   "MEDIUM  ",
        Severity.LOW:      "LOW     ",
        Severity.INFO:     "INFO    ",
    }

    print("\n" + "=" * 64)
    print(f"  IAM SCANNER — SCAN SUMMARY   {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 64)
    print(f"  {'SEVERITY':<12} {'COUNT':>6}   {'SLA'}")
    print("  " + "-" * 60)
    for sev in Severity:
        count = counts[sev]
        marker = " ◄ ACTION REQUIRED" if count > 0 and sev in (Severity.CRITICAL, Severity.HIGH) else ""
        print(f"  {sev_labels[sev]:<12} {count:>6}   {SEVERITY_SLA[sev]}{marker}")
    print("  " + "-" * 60)
    print(f"  {'TOTAL':<12} {len(findings):>6}")
    print("=" * 64)

    if findings:
        print("\n  FINDINGS DETAIL:")
        print("  " + "-" * 60)
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            print(f"  [{f.severity.value:<8}] {f.username:<20} {f.alert_type}")
            print(f"             Score: {f.risk_score:>2}  |  {f.sla}")
            print(f"             {f.detail[:80]}{'…' if len(f.detail) > 80 else ''}")
            print()
    print("=" * 64 + "\n")


# ===========================================================================
# 13. AI report generation
# ===========================================================================

def _build_safe_prompt(high_risk_findings: list[Finding]) -> str:
    """
    Build a sanitised LLM prompt from high-risk findings.

    All user-controlled field values are run through sanitise_for_prompt()
    before interpolation to mitigate prompt injection.

    Args:
        high_risk_findings: Findings with severity Critical or High.

    Returns:
        Sanitised prompt string.
    """
    safe_findings: list[dict[str, Any]] = [
        {
            "username":   sanitise_for_prompt(f.username),
            "alert_type": sanitise_for_prompt(f.alert_type),
            "severity":   f.severity.value,      # enum — always safe
            "risk_score": f.risk_score,           # int — always safe
            "detail":     sanitise_for_prompt(f.detail),
        }
        for f in high_risk_findings
    ]
    return (
        "You are a professional Security Analyst. "
        "Review the following high-severity IAM alerts and write a concise, "
        "professional incident report suitable for a technical manager. "
        "Group findings by severity. Recommend specific remediation steps. "
        "Do not speculate beyond what the data shows. "
        f"Alerts: {json.dumps(safe_findings)}"
    )


def generate_ai_summary(findings: list[Finding]) -> str | None:
    """
    Call the local Ollama LLM to generate an executive incident report
    for Critical and High severity findings.

    Returns None if there are no qualifying findings or the call fails.

    Args:
        findings: All new findings from this scan run.

    Returns:
        AI-generated report string, or None.
    """
    high_risk: list[Finding] = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if not high_risk:
        logger.info("No Critical/High findings — skipping AI summary.")
        return None

    prompt: str   = _build_safe_prompt(high_risk)
    endpoint: str = f"{OLLAMA_BASE_URL}/api/generate"

    try:
        response = requests.post(
            endpoint,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT_SEC,
        )
        response.raise_for_status()
        ai_text: str = response.json().get("response", "").strip()
        if not ai_text:
            logger.warning("AI engine returned an empty response.")
            return None
        logger.info("AI summary generated (%d chars).", len(ai_text))
        return ai_text

    except requests.exceptions.ConnectionError:
        logger.error("Cannot reach Ollama at %s — run: ollama serve", endpoint)
    except requests.exceptions.Timeout:
        logger.error("Ollama timed out after %ds.", OLLAMA_TIMEOUT_SEC)
    except requests.exceptions.HTTPError as exc:
        logger.error("Ollama HTTP error: %s", exc)
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Malformed Ollama response: %s", exc)

    return None


# ===========================================================================
# 14. Output: report file + JSON export
# ===========================================================================

def save_report_to_disk(report_content: str, username: str) -> str:
    """
    Save an AI-generated incident report to a text file for auditing.

    Filename: incident_<safe_username>_<timestamp>_<uuid6>.txt
    UUID suffix prevents collisions when multiple alerts fire per second.

    Args:
        report_content : Full text of the AI report.
        username       : IAM username (sanitised before use in filename).

    Returns:
        Absolute path of the saved file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    safe_user: str   = re.sub(r"[^a-zA-Z0-9_\-]", "_", username)[:64]
    timestamp: str   = time.strftime("%Y-%m-%d_%H-%M-%S")
    uid:       str   = uuid.uuid4().hex[:6]
    filepath:  str   = os.path.join(REPORTS_DIR, f"incident_{safe_user}_{timestamp}_{uid}.txt")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(report_content)
    logger.info("Report saved → %s", filepath)
    return filepath


def export_findings_json(findings: list[Finding]) -> str:
    """
    Serialise all findings to a structured JSON file for SIEM ingestion.

    Written atomically (temp-file rename). Includes severity counts,
    scan timestamp, and full finding details.

    Args:
        findings: All new findings from this scan run.

    Returns:
        Absolute path of the exported JSON file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp: str  = time.strftime("%Y-%m-%d_%H-%M-%S")
    out_path:  str  = os.path.join(REPORTS_DIR, f"scan_results_{timestamp}.json")

    severity_counts: dict[str, int] = {sev.value: 0 for sev in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1

    payload: dict[str, Any] = {
        "scan_timestamp":  timestamp,
        "total_findings":  len(findings),
        "severity_counts": severity_counts,
        "findings":        [f.to_dict() for f in findings],
    }

    tmp_fd, tmp_path = tempfile.mkstemp(dir=REPORTS_DIR, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=4)
        os.replace(tmp_path, out_path)
    except OSError:
        os.unlink(tmp_path)
        raise

    logger.info("Findings JSON → %s", out_path)
    return out_path


# ===========================================================================
# 15. Orchestrator
# ===========================================================================

def run_scanner() -> None:
    """
    Execute the full IAM security scan pipeline.

    Pipeline
    --------
    1.  Fetch live IAM inventory.
    2.  Load baseline (or initialise on first run).
    3.  Load active alert fingerprint state.
    4.  Run all detectors + field-level drift.
    5.  Deduplicate findings.
    6.  Print summary table to console.
    7.  Export structured JSON.
    8.  Generate AI executive report (Critical/High only).
    9.  Save per-user report files.
    10. Persist updated alert state + baseline.
    """
    logger.info("=" * 60)
    logger.info("IAM Security Scanner v2.0 — starting")
    logger.info("=" * 60)

    # Step 1: Inventory
    iam_data: list[UserRecord] = fetch_cloud_inventory()
    logger.info("Fetched %d user records.", len(iam_data))

    # Step 2: Baseline
    baseline: list[UserRecord] | None = load_baseline()
    first_run: bool = baseline is None
    if first_run:
        logger.info("First run — saving current state as baseline.")
        save_baseline(iam_data)
        baseline = []   # empty baseline → every user appears as "New User"

    # Step 3: Alert state (dedup)
    alert_state: dict[str, str] = load_alert_state()

    # Step 4 + 5: Run all checks and deduplicate
    new_findings, updated_alert_state = run_all_checks(iam_data, baseline, alert_state)

    # Step 6: Console summary
    print_summary_table(new_findings)

    if not new_findings:
        logger.info("No new findings this run. Scan complete.")
        save_alert_state(updated_alert_state)
        if not first_run:
            save_baseline(iam_data)
        return

    # Step 7: Export JSON
    json_path: str = export_findings_json(new_findings)
    logger.info("JSON findings written to: %s", json_path)

    # Step 8: AI report
    ai_report: str | None = generate_ai_summary(new_findings)
    if ai_report:
        print("\n" + "=" * 64)
        print("  AI EXECUTIVE REPORT")
        print("=" * 64)
        print(ai_report)
        print("=" * 64 + "\n")

        # Step 9: Save per-user files (one per unique username, Critical/High)
        seen: set[str] = set()
        for f in new_findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.username not in seen:
                save_report_to_disk(ai_report, f.username)
                seen.add(f.username)

    # Step 10: Persist state
    save_alert_state(updated_alert_state)
    if not first_run:
        save_baseline(iam_data)
        logger.info("Baseline updated.")

    logger.info("Scan complete. New findings this run: %d", len(new_findings))


# ===========================================================================
# 16. Entry point
# ===========================================================================

if __name__ == "__main__":
    run_scanner()