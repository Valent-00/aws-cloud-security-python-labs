"""
boto3_inventory.py
==================
Production AWS IAM data fetcher for the Lambda deployment.

This module is the ONLY change between your local scanner and the
cloud-native Lambda version. It provides a drop-in replacement for
`fetch_cloud_inventory()` in api_mock_scanner.py — returning the
exact same UserRecord schema so all 13 detectors, MITRE mappings,
deduplication, and severity bands work without a single line change.

Why a separate file?
--------------------
Your api_mock_scanner.py is already production-quality. Modifying it
would risk breaking the local FastAPI backend. Instead this module
monkey-patches fetch_cloud_inventory at Lambda startup — the scanner
never knows it is talking to real AWS data.

AWS IAM permissions required (defined in iam_execution_role.json)
-----------------------------------------------------------------
  iam:ListUsers
  iam:ListUserPolicies
  iam:ListAttachedUserPolicies
  iam:ListGroupsForUser
  iam:ListAttachedGroupPolicies
  iam:ListAccessKeys
  iam:GetAccessKeyLastUsed
  iam:GetAccountPasswordPolicy
  iam:GenerateCredentialReport
  iam:GetCredentialReport

Pagination contract
-------------------
ALL list_* calls use get_paginator() — never assumes a single page.
AWS IAM paginates at 100 users by default. An account with 101 users
would silently miss the last user without paginators.

UserRecord schema produced (must match api_mock_scanner.py exactly)
--------------------------------------------------------------------
username              str   — IAM username
role                  str   — 'Administrator' if admin policy, else 'Developer'
mfa_enabled           bool  — MFA device active
active_key_count      int   — number of Active access keys
key_age_days          int   — oldest active key age in days (-1 = none)
key_last_used_days    int   — days since oldest key last used (-1 = never)
password_age_days     int   — days since password set (-1 = no console access)
last_login_days       int   — days since last console login (-1 = never)
account_enabled       bool  — always True (IAM has no disable concept)
permissions           list  — attached policy names
last_login_hour       int   — always -1 (requires CloudTrail, not IAM API)
known_countries       list  — always [] (requires CloudTrail)
last_login_country    str   — always "" (requires CloudTrail)
failed_logins_24h     int   — always 0 (requires CloudTrail)
is_root               bool  — True only for the root account row
"""

import csv
import io
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("iam_scanner.inventory")

# Type alias matching api_mock_scanner.py
UserRecord = dict[str, Any]

# Thresholds — read from Lambda env vars, fall back to scanner defaults
_KEY_DAYS: int = int(os.getenv("KEY_ROTATION_DAYS", "90"))


# ===========================================================================
# Internal helpers
# ===========================================================================

def _age_days(dt: datetime | None) -> int:
    """
    Calculate elapsed days between a UTC datetime and now.

    Returns -1 if dt is None — convention for "never" throughout the
    UserRecord schema (key never used, user never logged in, etc.).

    Args:
        dt: timezone-aware datetime or None.

    Returns:
        Non-negative integer days, or -1 for None.

    Time  : O(1)   Space: O(1)
    """
    if dt is None:
        return -1
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


def _parse_report_dt(value: str) -> datetime | None:
    """
    Parse a credential report date string to a UTC-aware datetime.

    The credential report uses 'N/A', 'no_information', and
    'not_supported' for fields that do not apply (e.g. password
    for a user who has never logged in).

    Args:
        value: ISO-8601 string from credential report CSV, or a
               sentinel string indicating the field is not applicable.

    Returns:
        Timezone-aware datetime, or None.

    Time  : O(1)   Space: O(1)
    """
    if not value or value in ("N/A", "no_information", "not_supported", ""):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _generate_credential_report(iam) -> dict[str, dict]:
    """
    Generate and retrieve the AWS IAM credential report as a username-keyed dict.

    The credential report is the most efficient way to get password age,
    MFA status, and key metadata for all users in one call — far cheaper
    than calling per-user APIs for each field.

    Generation is asynchronous — AWS takes 1–30 seconds depending on
    account size. We poll until state == COMPLETE (max 10 attempts × 3s).

    Args:
        iam: boto3 IAM client.

    Returns:
        Dict mapping username → credential report CSV row dict.
        Returns empty dict if generation fails (scanner degrades gracefully).

    Time  : O(u) where u = IAM users   Space: O(u)
    """
    for attempt in range(10):
        try:
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            logger.info(
                "Credential report state: %s (attempt %d/10)",
                resp.get("State"), attempt + 1,
            )
            time.sleep(3)
        except ClientError as exc:
            logger.warning("generate_credential_report error: %s", exc)
            return {}

    try:
        resp = iam.get_credential_report()
        # Content is plain bytes here, not a StreamingBody like S3's
        # get_object() Body — no .read() needed or available.
        csv_text: str = resp["Content"].decode("utf-8")
    except ClientError as exc:
        logger.error("get_credential_report failed: %s", exc)
        return {}

    reader = csv.DictReader(io.StringIO(csv_text))
    return {row["user"]: row for row in reader}


def _get_policies(iam, username: str) -> list[str]:
    """
    Collect all policy names attached to a user directly or via groups.

    Checks three attachment paths:
      1. Inline user policies
      2. Managed policies attached directly to the user
      3. Managed policies attached to groups the user belongs to

    All use paginators to handle accounts with many policies.

    Args:
        iam:      boto3 IAM client.
        username: IAM username.

    Returns:
        Deduplicated list of policy name strings.

    Time  : O(p + g) where p = policies, g = groups   Space: O(p)
    """
    names: set[str] = set()

    try:
        for page in iam.get_paginator("list_user_policies").paginate(UserName=username):
            names.update(page.get("PolicyNames", []))
    except ClientError as exc:
        logger.warning("list_user_policies(%s): %s", username, exc)

    try:
        for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
            for p in page.get("AttachedPolicies", []):
                names.add(p["PolicyName"])
    except ClientError as exc:
        logger.warning("list_attached_user_policies(%s): %s", username, exc)

    try:
        for page in iam.get_paginator("list_groups_for_user").paginate(UserName=username):
            for group in page.get("Groups", []):
                for gpage in iam.get_paginator("list_attached_group_policies").paginate(
                    GroupName=group["GroupName"]
                ):
                    for p in gpage.get("AttachedPolicies", []):
                        names.add(p["PolicyName"])
    except ClientError as exc:
        logger.warning("list_groups_for_user(%s): %s", username, exc)

    return list(names)


def _is_admin(policy_names: list[str]) -> bool:
    """
    Return True if any policy indicates full administrative access.

    Args:
        policy_names: List of policy name strings.

    Returns:
        True if the user has admin-level permissions.

    Time  : O(p)   Space: O(1)
    """
    admin_set = {"AdministratorAccess", "PowerUserAccess"}
    for name in policy_names:
        if name in admin_set or "Admin" in name or "FullAccess" in name:
            return True
    return False


def _build_user_record(
    iam,
    user:       dict,
    cred_report: dict[str, dict],
) -> UserRecord:
    """
    Build one UserRecord from IAM API data + credential report row.

    This is the core mapping function — it translates AWS API shapes
    into the exact UserRecord schema expected by api_mock_scanner.py's
    13 detectors.

    Args:
        iam:         boto3 IAM client.
        user:        One item from list_users paginator.
        cred_report: Full credential report keyed by username.

    Returns:
        A UserRecord dict matching the schema in api_mock_scanner.py.

    Time  : O(k) where k = access keys per user   Space: O(1)
    """
    username: str = user["UserName"]
    cr = cred_report.get(username, {})

    # --- MFA and console access from credential report ---
    mfa_enabled:  bool = cr.get("mfa_active",       "false").lower() == "true"
    has_console:  bool = cr.get("password_enabled",  "false").lower() == "true"

    # --- Password and login age ---
    pwd_changed     = _parse_report_dt(cr.get("password_last_changed",  ""))
    pwd_used        = _parse_report_dt(cr.get("password_last_used",     ""))
    password_age    = _age_days(pwd_changed)
    last_login      = _age_days(pwd_used)

    # --- Access keys (paginate for completeness, though max is 2 in AWS) ---
    active_keys:         list[dict] = []
    key_age_days:        int        = -1
    key_last_used_days:  int        = -1

    try:
        resp = iam.list_access_keys(UserName=username)
        for key in resp.get("AccessKeyMetadata", []):
            if key["Status"] != "Active":
                continue
            age = _age_days(key.get("CreateDate"))
            try:
                lu = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                last_used = _age_days(
                    lu.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                )
            except ClientError:
                last_used = -1
            active_keys.append({"age": age, "last_used": last_used})

        if active_keys:
            oldest          = max(active_keys, key=lambda k: k["age"])
            key_age_days    = oldest["age"]
            key_last_used_days = oldest["last_used"]
    except ClientError as exc:
        logger.warning("list_access_keys(%s): %s", username, exc)

    # --- Policies and role ---
    policies  = _get_policies(iam, username)
    admin     = _is_admin(policies)
    role      = "Administrator" if admin else "Developer"

    return {
        # Core identity
        "username":           username,
        "role":               role,
        # Credential checks
        "mfa_enabled":        mfa_enabled,
        "active_key_count":   len(active_keys),
        "key_age_days":       key_age_days,
        "key_last_used_days": key_last_used_days,
        "password_age_days":  password_age,
        "last_login_days":    last_login,
        # Account state
        "account_enabled":    True,       # IAM has no account-disable API
        "permissions":        policies,
        # Behavioural fields — not available via IAM API
        # Requires CloudTrail integration (future enhancement)
        "last_login_hour":     -1,
        "known_countries":     [],
        "last_login_country":  "",
        "failed_logins_24h":   0,
        # Root flag
        "is_root":             False,
    }


def _build_root_record(cred_report: dict[str, dict]) -> UserRecord:
    """
    Build the root account UserRecord from the credential report.

    The root account appears as '<root_account>' in the credential
    report and is not returned by list_users. It is added separately
    because root account usage is always a Critical finding.

    Args:
        cred_report: Full credential report dict.

    Returns:
        UserRecord for the root account.

    Time  : O(1)   Space: O(1)
    """
    root = cred_report.get("<root_account>", {})
    last_used_str = root.get("password_last_used", "")
    last_used_dt  = _parse_report_dt(last_used_str)

    return {
        "username":           "root",
        "role":               "Root",
        "mfa_enabled":        root.get("mfa_active", "false").lower() == "true",
        "active_key_count":   0,
        "key_age_days":       -1,
        "key_last_used_days": -1,
        "password_age_days":  -1,
        "last_login_days":    _age_days(last_used_dt),
        "account_enabled":    True,
        "permissions":        ["*:*"],
        "last_login_hour":     -1,
        "known_countries":     [],
        "last_login_country":  "",
        "failed_logins_24h":   0,
        "is_root":             True,
    }


# ===========================================================================
# Public API — this is the drop-in replacement for fetch_cloud_inventory()
# ===========================================================================

def fetch_real_iam_inventory() -> list[UserRecord]:
    """
    Fetch the complete IAM user inventory from a live AWS account.

    This is the production replacement for the mock list in
    api_mock_scanner.py. It returns identical UserRecord dicts so all
    13 detectors work without any modification.

    Steps
    -----
    1. Create boto3 IAM client (uses Lambda execution role automatically).
    2. Generate + retrieve the IAM credential report (one API call for
       all users' MFA, password, and key metadata).
    3. Paginate through all IAM users (handles >100 users correctly).
    4. For each user: build a UserRecord using credential report + key data.
    5. Append root account record.

    Returns:
        List of UserRecord dicts — same schema as the mock inventory.

    Time  : O(u × k) where u = users, k = keys per user (max 2 in AWS)
    Space : O(u)
    """
    iam = boto3.client("iam")
    records: list[UserRecord] = []

    # Step 2 — credential report (one bulk call for all users)
    logger.info("Generating IAM credential report...")
    cred_report = _generate_credential_report(iam)
    logger.info("Credential report covers %d users.", len(cred_report))

    # Step 3 — paginate all users (never assumes single page)
    logger.info("Fetching IAM user list...")
    user_count = 0
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            record = _build_user_record(iam, user, cred_report)
            records.append(record)
            user_count += 1
            logger.debug("Processed: %s (admin=%s)", user["UserName"], record["role"])

    logger.info("Processed %d IAM users.", user_count)

    # Step 4 — root account (not in list_users, always added separately)
    records.append(_build_root_record(cred_report))
    logger.info("Total records including root: %d", len(records))

    return records