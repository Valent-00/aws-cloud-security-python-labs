"""
s3_reports.py
==============
Reads the historical scan reports written by lambda_function.py's
_upload_to_s3() after each scheduled Lambda run — the bridge between
the Lambda's real-boto3-data scans and the dashboard, which until now
only showed main.py's own scan history (and that pipeline still runs
against fetch_cloud_inventory()'s MOCK data, since the boto3 monkey-
patch only happens inside the Lambda's process).

S3 key layout this expects (written by lambda_function._upload_to_s3):
  scan_results/YYYY/MM/DD/<timestamp>.json
  scan_results/YYYY/MM/DD/<timestamp>_summary.txt

Report JSON shape (written by lambda_function.py's handler):
  {
    "report_type": "IAM Security Posture Scan",
    "scan_timestamp": ISO-8601 str,
    "aws_account_id": str,
    "aws_region": str,
    "total_findings": int,
    "severity_counts": {"Critical": int, "High": int, ...},
    "findings": [Finding.to_dict(), ...]
  }

Security fix — encryption-at-rest verification on read (Fix H-3, 2026-07)
--------------------------------------------------------------------------
lambda_function._upload_to_s3() writes every object with
ServerSideEncryption="AES256". get_s3_scan_report() verifies that
invariant still holds on read and logs (or, in strict mode, refuses) any
object S3 reports as unencrypted. See get_s3_scan_report for detail.

Security fix — S3 key prefix / traversal validation (Fix M-3, 2026-07)
-----------------------------------------------------------------------
The /api/v1/s3-reports/{key:path} route hands an analyst-supplied key
straight through to S3. Without validation, any authenticated caller
could request an arbitrary object in REPORT_BUCKET — not just the
scan reports under scan_results/ — turning a report viewer into a
general-purpose bucket reader (a broken-access-control / MITRE T1530
gap). is_safe_report_key() constrains every key to the scan_results/
prefix and rejects path-traversal segments, and is enforced BOTH at the
route edge (HTTP 400) and inside get_s3_scan_report() as a
defense-in-depth backstop so no future caller can bypass it.
"""
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("iam_scanner.s3_reports")

# Fix H-3: opt-in strict mode. When true, an object read without server-
# side encryption is refused (treated as unreadable) rather than merely
# logged. Default false preserves the existing dashboard behaviour.
_REQUIRE_ENCRYPTION: bool = os.getenv("S3_REQUIRE_ENCRYPTION", "false").lower() == "true"

# Fix M-3: every report key the API will read MUST live under this prefix.
# It is the same prefix lambda_function._upload_to_s3() writes to, so no
# legitimate report is ever excluded by it.
_ALLOWED_PREFIX: str = "scan_results/"


def is_safe_report_key(key: str) -> bool:
    """
    Return True only if `key` is a safe S3 object key for a scan report.

    A key is safe iff ALL of the following hold:
      * it is a non-empty string,
      * it contains no NUL byte and no backslash,
      * it does not start with "/",
      * none of its "/"-separated segments is empty, "." or ".."
        (path-traversal defense-in-depth — S3 keys are flat strings, but
        we never want ".." to reach a fetch, and this also protects any
        future code that caches a report to local disk by that key),
      * it starts with the allowed prefix and names an actual object
        beneath it (something exists after the prefix).

    This is a pure, side-effect-free predicate so it can be unit-tested in
    isolation and reused at every point a key enters the system.

    Args:
        key: The analyst-supplied S3 object key to validate.

    Returns:
        True if the key is safe to fetch, False otherwise.
    """
    if not isinstance(key, str):
        return False
    k = key.strip()
    if not k:
        return False
    if "\x00" in k or "\\" in k:
        return False
    if k.startswith("/"):
        return False
    if any(segment in ("", ".", "..") for segment in k.split("/")):
        return False
    if not k.startswith(_ALLOWED_PREFIX):
        return False
    if len(k) <= len(_ALLOWED_PREFIX):
        return False
    return True


def list_s3_scan_reports(bucket: str, max_results: int = 50) -> list[dict]:
    """
    List available scan report JSON keys in S3, newest first.

    Args:
        bucket:      The report bucket name (REPORT_BUCKET in deploy.sh).
        max_results: Maximum number of reports to return.

    Returns:
        List of {"key": str, "last_modified": ISO-8601 str,
        "size_bytes": int}, sorted newest-first. Empty list on any AWS
        error — callers should treat this as "no reports available
        right now", not a hard failure, matching the rest of this
        project's graceful-degradation pattern for AWS calls.

    Time  : O(n) where n = objects under scan_results/   Space: O(n)
    """
    s3 = boto3.client("s3")
    results: list[dict] = []
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix="scan_results/"):
            for obj in page.get("Contents", []):
                if obj["Key"].endswith(".json"):
                    results.append({
                        "key": obj["Key"],
                        "last_modified": obj["LastModified"].isoformat(),
                        "size_bytes": obj["Size"],
                    })
    except ClientError as exc:
        logger.error("Failed to list S3 scan reports in %s: %s", bucket, exc)
        return []

    results.sort(key=lambda r: r["last_modified"], reverse=True)
    return results[:max_results]


def get_s3_scan_report(bucket: str, key: str) -> dict | None:
    """
    Fetch and parse one scan report JSON from S3, verifying both that the
    key is in-prefix (Fix M-3) and that the object is encrypted at rest
    (Fix H-3).

    Args:
        bucket: The report bucket name.
        key:    The S3 object key, from list_s3_scan_reports().

    Returns:
        The parsed report dict, or None on any failure (unsafe key,
        missing key, access denied, malformed JSON) — never raises. If
        S3_REQUIRE_ENCRYPTION=true, also returns None for an object that
        S3 reports as not server-side-encrypted.

    Time  : O(f) where f = findings in the report   Space: O(f)
    """
    # Fix M-3 (defense-in-depth): the route layer already validates the key
    # and returns HTTP 400 for bad input, but re-check here so this function
    # is safe by default for ANY caller — an out-of-prefix or traversal key
    # never reaches boto3.
    if not is_safe_report_key(key):
        logger.warning(
            "Refusing to fetch unsafe or out-of-prefix S3 key: %r "
            "(must be under %r with no traversal segments).",
            key, _ALLOWED_PREFIX,
        )
        return None

    s3 = boto3.client("s3")
    try:
        response = s3.get_object(Bucket=bucket, Key=key)

        # Fix H-3: verify encryption-at-rest. S3 returns ServerSideEncryption
        # in the get_object response metadata whenever the object is encrypted
        # (by any method — "AES256" for SSE-S3, "aws:kms" for SSE-KMS). Its
        # absence means the object is NOT encrypted at rest, which violates the
        # invariant lambda_function._upload_to_s3() is supposed to guarantee.
        sse = response.get("ServerSideEncryption")
        if not sse:
            logger.warning(
                "S3 report %s/%s is NOT encrypted at rest (no "
                "ServerSideEncryption on the object). Expected AES256 as "
                "written by the Lambda. This object may have been written by "
                "an unexpected path — investigate.",
                bucket, key,
            )
            if _REQUIRE_ENCRYPTION:
                logger.error(
                    "S3_REQUIRE_ENCRYPTION=true — refusing to serve "
                    "unencrypted report %s/%s.", bucket, key,
                )
                return None

        # S3's get_object Body genuinely IS a StreamingBody (unlike IAM's
        # get_credential_report, where the .read() bug was fixed earlier
        # tonight) — .read() is correct and required here.
        body = response["Body"].read().decode("utf-8")
        return json.loads(body)
    except ClientError as exc:
        logger.error("Failed to fetch S3 report %s/%s: %s", bucket, key, exc)
        return None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.error("Malformed report at %s/%s: %s", bucket, key, exc)
        return None


def compare_scan_reports(older: dict, newer: dict) -> dict:
    """
    Compare two parsed scan reports by finding fingerprint — the same
    fingerprint concept already used everywhere else in this project
    for deduplication (AlertState.fingerprint, Finding.fingerprint),
    so "what changed between two scans" means the same thing here as
    it does everywhere else in the codebase.

    Args:
        older: Parsed report dict with the earlier scan_timestamp.
        newer: Parsed report dict with the later scan_timestamp.

    Returns:
        {
          "older_scan_timestamp": str,
          "newer_scan_timestamp": str,
          "new_findings":      [finding dicts present in newer, not older],
          "resolved_findings": [finding dicts present in older, not newer],
          "severity_count_delta": {"Critical": +1, "High": 0, ...},
        }

    Time  : O(f_older + f_newer)   Space: O(f_older + f_newer)
    """
    older_by_fp = {f["fingerprint"]: f for f in older.get("findings", [])}
    newer_by_fp = {f["fingerprint"]: f for f in newer.get("findings", [])}

    new_fps = set(newer_by_fp) - set(older_by_fp)
    resolved_fps = set(older_by_fp) - set(newer_by_fp)

    older_counts = older.get("severity_counts", {})
    newer_counts = newer.get("severity_counts", {})
    all_severities = set(older_counts) | set(newer_counts)
    delta = {
        sev: newer_counts.get(sev, 0) - older_counts.get(sev, 0)
        for sev in all_severities
    }

    return {
        "older_scan_timestamp": older.get("scan_timestamp"),
        "newer_scan_timestamp": newer.get("scan_timestamp"),
        "new_findings": [newer_by_fp[fp] for fp in new_fps],
        "resolved_findings": [older_by_fp[fp] for fp in resolved_fps],
        "severity_count_delta": delta,
    }