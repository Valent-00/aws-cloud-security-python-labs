"""
iam_compliance_scanner.py
--------------------------
Audits a mock IAM user inventory against two mandatory company compliance
policies and emits a structured terminal report with per-violation alerts
and an executive metrics summary.

Policies Enforced:
    [HIGH]   Policy 1 — Multi-Factor Authentication (MFA) must be enabled
             for every user, regardless of role.
    [MEDIUM] Policy 2 — Access keys must be rotated within 90 days; any
             key older than 90 days constitutes a stale-key violation.

Libraries:
    None — stdlib only (no third-party dependencies).

Usage:
    python iam_compliance_scanner.py
"""


# ---------------------------------------------------------------------------
# Mock IAM Identity Inventory
# Each dictionary represents one IAM principal with four tracked attributes.
# ---------------------------------------------------------------------------

identity_inventory: list[dict] = [
    {
        "username":    "admin_root",
        "mfa_enabled": True,
        "key_age_days": 115,
        "role":        "Administrator"
    },
    {
        "username":    "intern_dev01",
        "mfa_enabled": False,
        "key_age_days": 12,
        "role":        "Developer"
    },
    {
        "username":    "contractor_sec",
        "mfa_enabled": True,
        "key_age_days": 45,
        "role":        "SecurityAuditor"
    },
    {
        "username":    "stale_deployer",
        "mfa_enabled": False,
        "key_age_days": 210,
        "role":        "DevOps"
    },
]


# ---------------------------------------------------------------------------
# Compliance Scanner Function
# ---------------------------------------------------------------------------

def scan_iam_posture(users_list: list[dict]) -> None:
    """
    Audit every IAM user in `users_list` against the two mandatory
    compliance policies and print a formatted executive summary.

    Why `users_list` is a parameter rather than a hardcoded reference
    ------------------------------------------------------------------
    Accepting the inventory as a dynamic argument decouples the audit
    logic from any single, fixed data source. The same function can be
    called with different inventories — live API data, test fixtures,
    or subsets of a larger fleet — without modifying the function body:

        scan_iam_posture(identity_inventory)         # full production run
        scan_iam_posture(test_users)                 # unit-test fixture
        scan_iam_posture(api_response["IAMUsers"])   # live AWS SDK response

    Args:
        users_list: A list of IAM user dictionaries. Each dict must
                    contain the keys: "username", "mfa_enabled",
                    "key_age_days", and "role".

    Returns:
        None. Output is written to stdout as a structured terminal report.
    """

    # ── Compliance thresholds ───────────────────────────────────────────────
    KEY_ROTATION_LIMIT: int = 90     # days; keys older than this are stale

    # ── Violation counters (initialised before the loop to avoid KeyError) ──
    mfa_failure_count:  int = 0
    stale_key_count:    int = 0

    # ── Report header ───────────────────────────────────────────────────────
    width = 62
    print("=" * width)
    print("   IAM COMPLIANCE POSTURE SCAN — VIOLATION REPORT")
    print(f"   Users in scope: {len(users_list)}")
    print("=" * width)

    # ── Per-user audit loop ─────────────────────────────────────────────────
    # Iterate once over every user. Both policy checks are independent
    # `if` statements (NOT `elif`) so a user who violates both policies
    # correctly generates two separate alerts in the same pass.
    for user in users_list:

        username:    str  = user["username"]
        mfa_enabled: bool = user["mfa_enabled"]
        key_age:     int  = user["key_age_days"]
        role:        str  = user["role"]

        # ── Policy 1: MFA Enforcement ───────────────────────────────────────
        # Trigger: mfa_enabled is False (boolean equality, not truthiness
        # inversion, to guard against None or missing values in real data).
        if mfa_enabled is False:
            mfa_failure_count += 1
            print(f"\n  [HIGH] MFA NOT ENABLED — Policy 1 Violation")
            print(f"         Username : {username}")
            print(f"         Role     : {role}")
            print(f"         Action   : Enforce MFA immediately; suspend "
                  f"console access until resolved.")
            print(f"  {'-' * (width - 2)}")

        # ── Policy 2: Access Key Rotation ───────────────────────────────────
        # Trigger: key_age_days STRICTLY GREATER THAN 90 (not >=).
        # A key exactly 90 days old is still within the acceptable window.
        if key_age > KEY_ROTATION_LIMIT:
            stale_key_count += 1
            print(f"\n  [MEDIUM] STALE ACCESS KEY — Policy 2 Violation")
            print(f"           Username    : {username}")
            print(f"           Key Age     : {key_age} days "
                  f"({key_age - KEY_ROTATION_LIMIT} days overdue)")
            print(f"           Threshold   : {KEY_ROTATION_LIMIT} days")
            print(f"           Action      : Rotate key and update all "
                  f"dependent service credentials.")
            print(f"  {'-' * (width - 2)}")

    # ── Executive summary ───────────────────────────────────────────────────
    total_violations: int = mfa_failure_count + stale_key_count

    print()
    print("=" * width)
    print("   EXECUTIVE METRICS SUMMARY")
    print("=" * width)
    print(f"   Total Users Audited          : {len(users_list)}")
    print(f"   Total Critical MFA Failures  : {mfa_failure_count}")
    print(f"   Total Stale Key Violations   : {stale_key_count}")
    print(f"   ──────────────────────────────────────────────────")
    print(f"   Total Violations Found       : {total_violations}")

    # Compliance verdict — clean run vs. remediation required
    if total_violations == 0:
        print(f"\n   STATUS: ✓  ALL USERS COMPLIANT — No action required.")
    else:
        print(f"\n   STATUS: ✗  REMEDIATION REQUIRED — "
              f"{total_violations} violation(s) need immediate attention.")

    print("=" * width)


# ---------------------------------------------------------------------------
# Entry point
# The `if __name__ == "__main__"` guard ensures that:
#   (a) running `python iam_compliance_scanner.py` triggers the scan, AND
#   (b) importing this module in a test suite does NOT auto-execute the scan,
#       keeping the function freely testable in isolation.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    scan_iam_posture(identity_inventory)