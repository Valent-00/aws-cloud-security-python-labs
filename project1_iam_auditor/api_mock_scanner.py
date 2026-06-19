"""
api_mock_scanner.py
===================
IAM Security Posture Scanner with AI-Powered Incident Reporting

Architecture
------------
  fetch_cloud_inventory()        → raw user records (mock / real SDK swappable)
  detect_configuration_drift()   → compares against a saved baseline
  scan_iam_posture()             → checks MFA, stale keys
  calculate_risk_score()         → pure scoring function, no side effects
  save_baseline()                → persists baseline to disk (explicit, not hidden)
  generate_ai_summary()          → calls local Ollama LLM for executive report
  save_report_to_disk()          → writes one report file per incident
  run_scanner()                  → orchestrates the full pipeline

Security Notes
--------------
  * All user-supplied / external field values are sanitised before being
    interpolated into LLM prompts (prompt injection mitigation).
  * Baseline JSON is written atomically via a temp-file rename to prevent
    partial writes from corrupting state.
  * No secrets (API keys, passwords) appear anywhere in this file.
    All external config is loaded from environment variables or a .env file.
  * Specific exception types are caught — broad `except Exception` is avoided.

Usage
-----
  python api_mock_scanner.py

  Optional .env file keys:
      OLLAMA_BASE_URL      (default: http://localhost:11434)
      OLLAMA_MODEL         (default: llama3.2)
      OLLAMA_TIMEOUT_SEC   (default: 45)
      HIGH_RISK_THRESHOLD  (default: 70)
      KEY_ROTATION_DAYS    (default: 90)
"""

# ---------------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------------
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# 1. Load environment variables from .env (if present)
#    Falls back to real environment variables silently when .env is absent.
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# 2. Logging — structured, consistent format, written to both console + file
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 3. Configuration — read from environment, with safe defaults
#    No secrets live in source code. All business-rule constants are here,
#    not scattered through the logic.
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT_SEC: int = int(os.getenv("OLLAMA_TIMEOUT_SEC", "45"))
HIGH_RISK_THRESHOLD: int = int(os.getenv("HIGH_RISK_THRESHOLD", "70"))
KEY_ROTATION_LIMIT_DAYS: int = int(os.getenv("KEY_ROTATION_DAYS", "90"))

STATE_DIR: str = os.path.join(SCRIPT_DIR, "state")
STATE_FILE_PATH: str = os.path.join(STATE_DIR, "baseline_iam.json")
REPORTS_DIR: str = os.path.join(SCRIPT_DIR, "reports")

# Risk scoring constants — centralised so a security lead can adjust them
RISK_BASE_SCORES: dict[str, int] = {
    "MFA Disabled":     50,
    "New User Created": 40,
    "Stale Key":        20,
    "Role Changed":     60,
}
ADMIN_ROLE_MULTIPLIER: float = 1.5
MAX_RISK_SCORE: int = 99

# Regex for sanitising untrusted string values before prompt interpolation.
# Strips common prompt-injection patterns: newline sequences, triple backticks,
# angle-bracket tags, and "ignore previous instructions" variants.
_PROMPT_INJECTION_PATTERN: re.Pattern[str] = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?"
    r"|<[^>]{0,200}>"           # HTML / XML tags
    r"|```"                     # Markdown code fence
    r"|\r\n|\r|\n"              # Newline variants
    r"|\x00)",                  # Null byte
    flags=re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 4. Type aliases — makes function signatures self-documenting
# ---------------------------------------------------------------------------
UserRecord = dict[str, Any]          # e.g. {"username": ..., "mfa_enabled": ...}
Finding = dict[str, Any]             # e.g. {"username": ..., "alert_type": ..., "risk_score": ...}


# ===========================================================================
# 5. Helper: Input sanitisation
# ===========================================================================

def sanitise_for_prompt(value: str) -> str:
    """
    Remove prompt-injection patterns from a string value before it is
    interpolated into an LLM prompt.

    This is a defence-in-depth measure. It does not guarantee safety against
    all adversarial inputs, but it removes the most common attack vectors.

    Args:
        value: The raw string (e.g. a username, role name) from external data.

    Returns:
        A cleaned string safe to include in a prompt.
    """
    cleaned: str = _PROMPT_INJECTION_PATTERN.sub(" ", value)
    # Hard-cap length so a long injected string cannot overflow context
    return cleaned[:128].strip()


# ===========================================================================
# 6. Core logic: Risk scoring (pure function — no side effects)
# ===========================================================================

def calculate_risk_score(
    incident_type: str,
    user_role: str,
    key_age: int = 0,
) -> int:
    """
    Calculate a normalised risk score (0–99) for a given incident.

    Scoring rules:
    - Base score comes from RISK_BASE_SCORES lookup.
    - Stale Key: +1 point per day beyond KEY_ROTATION_LIMIT_DAYS.
    - Administrator role: score multiplied by ADMIN_ROLE_MULTIPLIER.
    - Final score is capped at MAX_RISK_SCORE (99) and rounded to int.

    Args:
        incident_type: One of "MFA Disabled", "Stale Key", "New User Created",
                       "Role Changed".
        user_role:     The IAM role of the user (e.g. "Administrator").
        key_age:       Age of the API key in days (used for "Stale Key" type).

    Returns:
        Integer risk score in the range [0, MAX_RISK_SCORE].
    """
    score: float = RISK_BASE_SCORES.get(incident_type, 0)

    if incident_type == "Stale Key" and key_age > KEY_ROTATION_LIMIT_DAYS:
        score += key_age - KEY_ROTATION_LIMIT_DAYS

    if user_role == "Administrator":
        score *= ADMIN_ROLE_MULTIPLIER

    return min(round(score), MAX_RISK_SCORE)


# ===========================================================================
# 7. Data source: Inventory fetch (swappable mock → real SDK)
# ===========================================================================

def fetch_cloud_inventory() -> list[UserRecord]:
    """
    Return a list of IAM user records.

    ARCHITECTURE NOTE
    -----------------
    This function is the *only* place that knows where user data comes from.
    The rest of the scanner never touches a data source directly.

    To connect to a real cloud provider (AWS, GCP, Azure), replace the body
    of this function with the appropriate SDK call — no other function needs
    to change.

    Returns:
        A list of dicts, each containing:
          - username    (str)
          - mfa_enabled (bool)
          - key_age_days (int)
          - role        (str)
    """
    # --- MOCK DATA (replace this block with your real SDK call) ---
    return [
        {
            "username":     "admin_root",
            "mfa_enabled":  False,
            "key_age_days": 115,
            "role":         "Administrator",
        },
        {
            "username":     "intern_dev01",
            "mfa_enabled":  False,
            "key_age_days": 12,
            "role":         "Developer",
        },
        {
            "username":     "stale_deployer",
            "mfa_enabled":  False,
            "key_age_days": 210,
            "role":         "DevOps",
        },
    ]


# ===========================================================================
# 8. Baseline state management (read / write decoupled)
# ===========================================================================

def load_baseline() -> list[UserRecord] | None:
    """
    Load the saved IAM baseline from disk.

    Returns:
        The baseline as a list of UserRecord dicts, or None if no
        baseline file exists yet.

    Raises:
        json.JSONDecodeError: If the file exists but contains invalid JSON.
        OSError:              If the file cannot be read due to permissions.
    """
    if not os.path.exists(STATE_FILE_PATH):
        return None

    with open(STATE_FILE_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_baseline(data: list[UserRecord]) -> None:
    """
    Persist the current IAM inventory as the new baseline.

    Uses an atomic write (write to a temp file, then rename) to prevent
    a partial baseline from corrupting state on crash or power loss.

    Args:
        data: The current list of UserRecord dicts to save as baseline.

    Raises:
        OSError: If the directory cannot be created or the file renamed.
    """
    os.makedirs(STATE_DIR, exist_ok=True)

    # Write to a temp file first, then rename atomically
    tmp_fd, tmp_path = tempfile.mkstemp(dir=STATE_DIR, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        os.replace(tmp_path, STATE_FILE_PATH)  # atomic on POSIX
        logger.info("Baseline saved to %s", STATE_FILE_PATH)
    except OSError:
        os.unlink(tmp_path)  # clean up temp file on failure
        raise


# ===========================================================================
# 9. Detection: Configuration drift
# ===========================================================================

def detect_configuration_drift(
    current_data: list[UserRecord],
    baseline_data: list[UserRecord],
) -> list[Finding]:
    """
    Compare the current IAM snapshot against a saved baseline to detect
    newly added user accounts.

    DESIGN NOTE: This function is now a pure comparison — it receives both
    datasets as arguments and returns findings. It does NOT read or write
    disk. The caller (run_scanner) owns the baseline lifecycle.

    Args:
        current_data:  The live IAM inventory.
        baseline_data: The previously saved baseline.

    Returns:
        A list of Finding dicts for each user not present in the baseline.
    """
    baseline_usernames: set[str] = {
        user["username"] for user in baseline_data
    }

    drift_alerts: list[Finding] = []
    for user in current_data:
        if user["username"] not in baseline_usernames:
            drift_alerts.append({
                "username":   user["username"],
                "alert_type": "New User Created",
                "risk_score": calculate_risk_score(
                    "New User Created", user["role"]
                ),
            })
            logger.warning(
                "Drift detected — new user: %s (role: %s)",
                user["username"], user["role"],
            )

    return drift_alerts


# ===========================================================================
# 10. Detection: IAM posture scan
# ===========================================================================

def scan_iam_posture(users_list: list[UserRecord]) -> list[Finding]:
    """
    Scan a list of IAM users for security misconfigurations.

    Currently checks:
      - MFA disabled for any user
      - Stale API keys (age > KEY_ROTATION_LIMIT_DAYS)

    Args:
        users_list: The current IAM inventory returned by fetch_cloud_inventory.

    Returns:
        A list of Finding dicts, one per misconfiguration detected.
    """
    findings: list[Finding] = []

    for user in users_list:
        username: str = user.get("username", "unknown")
        role: str = user.get("role", "Unknown")
        key_age: int = user.get("key_age_days", 0)

        # --- Check 1: MFA disabled ---
        if user.get("mfa_enabled") is False:
            score = calculate_risk_score("MFA Disabled", role)
            findings.append({
                "username":   username,
                "alert_type": "MFA Disabled",
                "risk_score": score,
            })
            logger.warning("MFA disabled — user: %s, risk score: %d", username, score)

        # --- Check 2: Stale API key ---
        if key_age > KEY_ROTATION_LIMIT_DAYS:
            score = calculate_risk_score("Stale Key", role, key_age)
            findings.append({
                "username":   username,
                "alert_type": "Stale Key",
                "risk_score": score,
                "key_age_days": key_age,
            })
            logger.warning(
                "Stale key — user: %s, age: %d days, risk score: %d",
                username, key_age, score,
            )

    return findings


# ===========================================================================
# 11. AI Report generation
# ===========================================================================

def _build_safe_prompt(high_risk_findings: list[Finding]) -> str:
    """
    Build an LLM prompt from high-risk findings after sanitising all
    user-controlled field values to mitigate prompt injection.

    Args:
        high_risk_findings: Findings with risk_score >= HIGH_RISK_THRESHOLD.

    Returns:
        A sanitised prompt string ready to send to the LLM.
    """
    safe_findings: list[dict[str, Any]] = []
    for finding in high_risk_findings:
        safe_findings.append({
            "username":   sanitise_for_prompt(str(finding.get("username", ""))),
            "alert_type": sanitise_for_prompt(str(finding.get("alert_type", ""))),
            "risk_score": int(finding.get("risk_score", 0)),  # always a safe int
        })

    return (
        "You are a professional Security Analyst. "
        "Review the following high-risk IAM alerts and write a concise, "
        "professional incident report suitable for a technical manager. "
        "Do not speculate beyond what the data shows. "
        f"Alerts: {json.dumps(safe_findings)}"
    )


def generate_ai_summary(findings: list[Finding]) -> str | None:
    """
    Send high-risk findings to a local Ollama LLM and return an AI-generated
    executive incident report.

    Error handling covers the distinct failure modes separately:
      - Server not running  → ConnectionError
      - Slow response       → Timeout
      - HTTP 4xx/5xx        → HTTPError (raised by raise_for_status)
      - Malformed JSON body → JSONDecodeError

    Args:
        findings: The full list of findings from this scan run.

    Returns:
        The AI-generated report as a string, or None if no high-risk
        findings exist or the LLM call fails.
    """
    high_risk: list[Finding] = [
        f for f in findings if f.get("risk_score", 0) >= HIGH_RISK_THRESHOLD
    ]

    if not high_risk:
        logger.info("No findings above risk threshold %d — skipping AI summary.", HIGH_RISK_THRESHOLD)
        return None

    prompt: str = _build_safe_prompt(high_risk)
    endpoint: str = f"{OLLAMA_BASE_URL}/api/generate"

    try:
        response = requests.post(
            endpoint,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT_SEC,
        )
        response.raise_for_status()

        result: dict[str, Any] = response.json()
        ai_text: str = result.get("response", "").strip()

        if not ai_text:
            logger.warning("AI engine returned an empty response.")
            return None

        logger.info("AI summary generated successfully (%d chars).", len(ai_text))
        return ai_text

    except requests.exceptions.ConnectionError:
        logger.error(
            "Cannot reach Ollama at %s — is the server running? "
            "Start it with: ollama serve",
            endpoint,
        )
    except requests.exceptions.Timeout:
        logger.error(
            "Ollama request timed out after %ds. "
            "Try increasing OLLAMA_TIMEOUT_SEC.",
            OLLAMA_TIMEOUT_SEC,
        )
    except requests.exceptions.HTTPError as exc:
        logger.error("Ollama returned HTTP error: %s", exc)
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Failed to parse Ollama response body: %s", exc)

    return None


# ===========================================================================
# 12. Report persistence
# ===========================================================================

def save_report_to_disk(report_content: str, username: str) -> str:
    """
    Save an AI-generated incident report to a text file for auditing.

    Filename format: incident_<username>_<timestamp>_<uuid6>.txt
    The UUID suffix prevents collisions when the same user triggers
    multiple alerts within the same second.

    Args:
        report_content: The full text of the AI-generated report.
        username:       The IAM username this report relates to.

    Returns:
        The absolute path of the saved report file.

    Raises:
        OSError: If the reports directory cannot be created or the file
                 cannot be written.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Sanitise username for safe filesystem use (whitelist: alphanumeric + _ -)
    safe_username: str = re.sub(r"[^a-zA-Z0-9_\-]", "_", username)[:64]
    timestamp: str = time.strftime("%Y-%m-%d_%H-%M-%S")
    uid_suffix: str = uuid.uuid4().hex[:6]  # 6-char collision breaker

    filename: str = os.path.join(
        REPORTS_DIR,
        f"incident_{safe_username}_{timestamp}_{uid_suffix}.txt",
    )

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(report_content)

    logger.info("Report saved → %s", filename)
    return filename


# ===========================================================================
# 13. Structured JSON output (machine-readable findings export)
# ===========================================================================

def export_findings_json(findings: list[Finding]) -> str:
    """
    Serialise all findings to a JSON file so downstream SIEM or
    analytics tools can consume them without parsing plain text.

    File is written atomically (temp → rename).

    Args:
        findings: The complete list of findings from this scan run.

    Returns:
        The absolute path of the exported JSON file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp: str = time.strftime("%Y-%m-%d_%H-%M-%S")
    output_path: str = os.path.join(REPORTS_DIR, f"scan_results_{timestamp}.json")

    payload: dict[str, Any] = {
        "scan_timestamp": timestamp,
        "total_findings": len(findings),
        "high_risk_count": sum(
            1 for f in findings if f.get("risk_score", 0) >= HIGH_RISK_THRESHOLD
        ),
        "findings": findings,
    }

    tmp_fd, tmp_path = tempfile.mkstemp(dir=REPORTS_DIR, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=4)
        os.replace(tmp_path, output_path)
    except OSError:
        os.unlink(tmp_path)
        raise

    logger.info("Findings exported → %s", output_path)
    return output_path


# ===========================================================================
# 14. Orchestrator — ties the pipeline together
# ===========================================================================

def run_scanner() -> None:
    """
    Execute the full IAM security scan pipeline.

    Pipeline steps:
      1. Fetch the live IAM inventory.
      2. Load (or initialise) the saved baseline.
      3. Detect drift between baseline and current inventory.
      4. Scan for IAM misconfigurations (MFA, stale keys).
      5. Export all findings as structured JSON.
      6. Generate an AI executive summary for high-risk incidents.
      7. Save individual report files per high-risk alert.
      8. Update the baseline to the current snapshot.
    """
    logger.info("=" * 60)
    logger.info("IAM Security Scanner — starting")
    logger.info("=" * 60)

    # --- Step 1: Fetch inventory ---
    iam_data: list[UserRecord] = fetch_cloud_inventory()
    logger.info("Fetched %d user records.", len(iam_data))

    # --- Step 2: Load baseline ---
    baseline: list[UserRecord] | None = load_baseline()
    first_run: bool = baseline is None

    if first_run:
        logger.info("No baseline found — this is the first run. Saving current state as baseline.")
        save_baseline(iam_data)
        baseline = iam_data

    # --- Step 3: Detect configuration drift ---
    drift_findings: list[Finding] = detect_configuration_drift(iam_data, baseline)
    logger.info("Drift check: %d new user(s) detected.", len(drift_findings))

    # --- Step 4: Posture scan ---
    posture_findings: list[Finding] = scan_iam_posture(iam_data)
    logger.info("Posture scan: %d misconfiguration(s) found.", len(posture_findings))

    # --- Step 5: Combine all findings ---
    all_findings: list[Finding] = drift_findings + posture_findings
    logger.info("Total findings: %d", len(all_findings))

    if not all_findings:
        logger.info("No issues found. Scan complete.")
        return

    # --- Step 6: Export structured JSON ---
    json_path: str = export_findings_json(all_findings)
    logger.info("Structured findings written to: %s", json_path)

    # --- Step 7: AI summary ---
    ai_report: str | None = generate_ai_summary(all_findings)

    if ai_report:
        print("\n" + "=" * 60)
        print(" AI EXECUTIVE REPORT")
        print("=" * 60)
        print(ai_report)
        print("=" * 60 + "\n")

        # Save one report file per high-risk user
        high_risk_findings: list[Finding] = [
            f for f in all_findings if f.get("risk_score", 0) >= HIGH_RISK_THRESHOLD
        ]
        seen_usernames: set[str] = set()
        for finding in high_risk_findings:
            uname: str = finding.get("username", "unknown")
            if uname not in seen_usernames:  # one file per user, not per alert
                save_report_to_disk(ai_report, uname)
                seen_usernames.add(uname)

    # --- Step 8: Update baseline to current snapshot ---
    if not first_run:
        save_baseline(iam_data)
        logger.info("Baseline updated with current snapshot.")

    logger.info("Scan complete.")


# ===========================================================================
# 15. Entry point
# ===========================================================================

if __name__ == "__main__":
    run_scanner()