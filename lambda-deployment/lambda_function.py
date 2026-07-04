"""
lambda_function.py
==================
AWS Lambda entry point for the IAM Security Posture Scanner.

How it works
------------
Your api_mock_scanner.py is left completely untouched. This file:
  1. Imports api_mock_scanner as a module.
  2. Monkey-patches scanner.fetch_cloud_inventory with the real boto3
     version BEFORE calling run_all_checks().
  3. Calls the same run_all_checks() your local FastAPI backend calls.
  4. Writes a JSON + text report to S3.
  5. Returns a structured summary to EventBridge / CloudWatch Logs.

This means every improvement you make to the scanner locally (new
detectors, new MITRE mappings, tuned risk scores) is automatically
picked up by the Lambda on next deploy — no Lambda-specific changes.

Trigger
-------
Amazon EventBridge scheduled rule: rate(1 day)
Fires at the same UTC time every 24 hours.

Environment variables (set in Lambda configuration)
----------------------------------------------------
  REPORT_BUCKET          S3 bucket name (required for report storage)
  KEY_ROTATION_DAYS      Key rotation threshold in days (default: 90)
  PASSWORD_MAX_AGE_DAYS  Password age threshold in days (default: 90)
  STALE_ACCOUNT_DAYS     Stale account threshold in days (default: 60)
  DORMANT_ADMIN_DAYS     Dormant admin threshold in days (default: 30)
  MAX_ACTIVE_KEYS_PER_USER  Max active keys per user (default: 1)
  LOG_LEVEL              Python log level string (default: INFO)

Response format (returned to EventBridge and visible in CloudWatch)
-------------------------------------------------------------------
{
  "statusCode":      200,
  "scan_timestamp":  "2026-06-22T03:18:00+00:00",
  "aws_account_id":  "123456789012",
  "total_findings":  28,
  "severity_counts": {"Critical": 6, "High": 4, "Medium": 14, ...},
  "s3_json_key":     "scan_results/2026/06/22/...",
  "s3_text_key":     "scan_results/2026/06/22/..._summary.txt"
}

On failure: {"statusCode": 500, "error": "...", "scan_timestamp": "..."}
"""

import json
import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Path setup — scanner package is in ./scanner/
# ---------------------------------------------------------------------------
_LAMBDA_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_LAMBDA_DIR))

# ---------------------------------------------------------------------------
# Logging — CloudWatch Logs receives everything at INFO+
# ---------------------------------------------------------------------------
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("iam_scanner.lambda")

# ---------------------------------------------------------------------------
# Import scanner internals AFTER path setup
# ---------------------------------------------------------------------------
from shared import scanner_engine as scanner
from shared.boto3_inventory import fetch_real_iam_inventory
from shared.notifications import notify_if_critical_or_high

# ---------------------------------------------------------------------------
# Monkey-patch: swap the mock inventory for the real boto3 fetcher.
# This is the ONLY change vs the local scanner. All 13 detectors, MITRE
# mappings, severity bands, and deduplication work without modification.
# ---------------------------------------------------------------------------
scanner.fetch_cloud_inventory = fetch_real_iam_inventory
logger.info("fetch_cloud_inventory patched → real AWS boto3 inventory.")


# ===========================================================================
# Report helpers
# ===========================================================================

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _severity_counts(findings: list) -> dict[str, int]:
    """Count findings per severity band."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.to_dict()["severity"] if hasattr(f, "to_dict") else f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _build_text_summary(
    findings:   list,
    scan_time:  str,
    account_id: str,
) -> str:
    """
    Build a human-readable text report for CloudWatch Logs and S3.

    Args:
        findings:   List of Finding dataclass instances.
        scan_time:  ISO-8601 UTC timestamp.
        account_id: AWS account ID.

    Returns:
        Multi-line string report.
    """
    counts = _severity_counts(findings)
    sla_map = {
        "Critical": "Respond within 1 hour",
        "High":     "Respond within 4 hours",
        "Medium":   "Respond within 24 hours",
        "Low":      "Respond within 72 hours",
        "Info":     "No SLA",
    }
    lines = [
        "=" * 70,
        "  IAM SECURITY POSTURE SCAN REPORT",
        f"  AWS Account : {account_id}",
        f"  Scan Time   : {scan_time}",
        f"  Total       : {len(findings)} findings",
        "=" * 70,
        "",
        "SEVERITY SUMMARY",
        "-" * 40,
    ]
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count  = counts.get(sev, 0)
        marker = "  ◄ ACTION REQUIRED" if count > 0 and sev in ("Critical", "High") else ""
        lines.append(f"  {sev:<10} {count:>4}   {sla_map[sev]}{marker}")

    lines += ["", "FINDINGS DETAIL", "-" * 70]

    sorted_findings = sorted(
        findings,
        key=lambda x: (
            _SEV_ORDER.get(x.to_dict()["severity"] if hasattr(x, "to_dict") else x.get("severity", "Info"), 4),
            -(x.to_dict()["risk_score"] if hasattr(x, "to_dict") else x.get("risk_score", 0)),
        ),
    )

    for f in sorted_findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        lines += [
            f"  [{d.get('severity', ''):<8}] {d.get('username', '')}",
            f"  Alert    : {d.get('alert_type', '')}",
            f"  Score    : {d.get('risk_score', 0)}  |  SLA: {d.get('sla', '')}",
            f"  Detail   : {d.get('detail', '')}",
        ]
        # MITRE ATT&CK reference if available
        if d.get("mitre_technique"):
            lines.append(
                f"  MITRE    : {d['mitre_technique']} — {d.get('mitre_tactic', '')}"
            )
        lines.append("")

    lines += ["=" * 70, "  END OF REPORT", "=" * 70]
    return "\n".join(lines)


def _upload_to_s3(
    json_payload: dict,
    text_report:  str,
    scan_time:    str,
) -> dict[str, str | None]:
    """
    Upload JSON and text reports to S3 with date-partitioned prefixes.

    Files are stored as:
      scan_results/YYYY/MM/DD/<timestamp>.json
      scan_results/YYYY/MM/DD/<timestamp>_summary.txt

    The date prefix enables S3 Lifecycle rules to expire old reports.
    Both files use AES-256 server-side encryption.

    Args:
        json_payload: JSON-serialisable report dict.
        text_report:  Human-readable report string.
        scan_time:    ISO-8601 UTC timestamp.

    Returns:
        Dict with 'json_key' and 'text_key' S3 object keys (or None if
        REPORT_BUCKET is not configured).

    Time  : O(f) — serialisation   Space: O(f)
    """
    bucket = os.getenv("REPORT_BUCKET", "")
    if not bucket:
        logger.warning(
            "REPORT_BUCKET env var not set — reports logged to CloudWatch only."
        )
        return {"json_key": None, "text_key": None}

    s3 = boto3.client("s3")
    dt = datetime.fromisoformat(scan_time.replace("Z", "+00:00"))
    prefix = f"scan_results/{dt.year}/{dt.month:02d}/{dt.day:02d}"
    ts = scan_time.replace(":", "-").replace("+", "-")[:19]

    json_key = f"{prefix}/{ts}.json"
    text_key = f"{prefix}/{ts}_summary.txt"

    # Atomic write via temp file then rename is not possible in S3;
    # use put_object which is atomic at the object level in S3.
    try:
        s3.put_object(
            Bucket=bucket,
            Key=json_key,
            Body=json.dumps(json_payload, indent=2).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info("JSON report → s3://%s/%s", bucket, json_key)
    except ClientError as exc:
        logger.error("Failed to upload JSON report: %s", exc)
        json_key = None

    try:
        s3.put_object(
            Bucket=bucket,
            Key=text_key,
            Body=text_report.encode("utf-8"),
            ContentType="text/plain",
            ServerSideEncryption="AES256",
        )
        logger.info("Text report → s3://%s/%s", bucket, text_key)
    except ClientError as exc:
        logger.error("Failed to upload text report: %s", exc)
        text_key = None

    return {"json_key": json_key, "text_key": text_key}


# ===========================================================================
# Lambda handler
# ===========================================================================

def handler(event: dict, context) -> dict[str, Any]:
    """
    Lambda handler — orchestrates the full IAM security scan pipeline.

    Pipeline
    --------
    1.  Record scan start time + extract AWS account ID from Lambda context.
    2.  Fetch live IAM inventory via boto3 (monkey-patched into scanner).
    3.  Load baseline from /tmp (Lambda ephemeral storage, per-execution).
    4.  Load alert deduplication state from /tmp.
    5.  Run all 13 detectors + field-level drift via scanner.run_all_checks().
    6.  Build JSON and text reports including MITRE ATT&CK mappings.
    7.  Upload both reports to S3.
    8.  Return structured summary (visible in CloudWatch + EventBridge).

    Note on /tmp state
    ------------------
    Lambda's /tmp (512MB ephemeral storage) persists within a warm
    container but is wiped on cold starts. This means deduplication
    state resets on cold starts — every cold-start scan reports all
    findings as new. This is acceptable for a daily scheduled scan
    and is the correct behaviour for a cloud-native tool (no stale
    suppression of ongoing misconfigurations). For persistent state,
    swap the JSON file baseline for a DynamoDB table (future enhancement).

    Args:
        event:   EventBridge scheduled event payload (not used directly).
        context: Lambda context (provides account ID via ARN, region).

    Returns:
        Dict with statusCode, severity counts, and S3 report keys.
    """
    scan_time  = datetime.now(timezone.utc).isoformat()
    account_id = "unknown"
    region     = os.getenv("AWS_REGION", "unknown")

    # Extract account ID from Lambda function ARN
    try:
        account_id = context.invoked_function_arn.split(":")[4]
    except (AttributeError, IndexError):
        pass  # context mock in local testing

    logger.info("=" * 60)
    logger.info("IAM Security Scanner Lambda — starting")
    logger.info("Account: %s | Region: %s | Time: %s", account_id, region, scan_time)
    logger.info("=" * 60)

    try:
        # Use /tmp for state files — Lambda ephemeral storage
        tmp_state_dir  = "/tmp/iam_scanner_state"
        os.makedirs(tmp_state_dir, exist_ok=True)

        # Override scanner's state paths to use /tmp
        # (Lambda execution environment is read-only except /tmp)
        # save_baseline()/save_alert_state() both call os.makedirs(STATE_DIR, ...)
        # before writing — STATE_DIR has to be overridden too, not just the
        # two file paths, or that makedirs() call still targets the
        # read-only /var/task/scanner/state from the original module.
        scanner.STATE_DIR        = tmp_state_dir
        scanner.STATE_FILE_PATH  = os.path.join(tmp_state_dir, "baseline_iam.json")
        scanner.ALERT_STATE_PATH = os.path.join(tmp_state_dir, "alert_state.json")

        # Step 2 — inventory (calls real boto3 via monkey-patch)
        logger.info("Step 1/4: Fetching live IAM inventory...")
        iam_data = scanner.fetch_cloud_inventory()
        logger.info("Fetched %d user records.", len(iam_data))

        # Step 3 + 4 — baseline and alert state
        baseline      = scanner.load_baseline() or []
        alert_state   = scanner.load_alert_state()
        first_run     = not bool(baseline)
        if first_run:
            logger.info("First run — saving baseline.")
            scanner.save_baseline(iam_data)
            baseline = []

        # Step 5 — run all checks (13 detectors + drift)
        logger.info("Step 2/4: Running security detectors...")
        new_findings, updated_alert_state = scanner.run_all_checks(
            iam_data, baseline, alert_state
        )
        logger.info("Detection complete — %d new findings.", len(new_findings))

        # Step 6 — build reports
        logger.info("Step 3/4: Building reports...")
        finding_dicts = [f.to_dict() for f in new_findings]
        severity_counts = _severity_counts(new_findings)

        json_payload = {
            "report_type":      "IAM Security Posture Scan",
            "scan_timestamp":   scan_time,
            "aws_account_id":   account_id,
            "aws_region":       region,
            "total_findings":   len(new_findings),
            "severity_counts":  severity_counts,
            "findings":         sorted(
                finding_dicts,
                key=lambda x: (_SEV_ORDER.get(x.get("severity", "Info"), 4), -x.get("risk_score", 0)),
            ),
        }

        text_report = _build_text_summary(new_findings, scan_time, account_id)

        # Always log the text report to CloudWatch
        logger.info("\n%s", text_report)

        # Step 7 — upload to S3
        logger.info("Step 4/4: Uploading reports to S3...")
        s3_keys = _upload_to_s3(json_payload, text_report, scan_time)

        # Step 8 — Slack/Teams alert on Critical/High (best-effort —
        # same pattern as every other optional/external step in this
        # handler: never let a notification failure mark a successful
        # scan as failed).
        try:
            notify_if_critical_or_high(
                findings=finding_dicts,
                severity_counts=severity_counts,
                scan_timestamp=scan_time,
                dashboard_url=os.getenv("DASHBOARD_URL") or None,
            )
        except Exception:
            logger.warning("Slack/Teams notification failed.", exc_info=True)

        # Persist updated state + baseline
        scanner.save_alert_state(updated_alert_state)
        if not first_run:
            scanner.save_baseline(iam_data)

        logger.info(
            "Scan complete — Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d",
            severity_counts.get("Critical", 0),
            severity_counts.get("High",     0),
            severity_counts.get("Medium",   0),
            severity_counts.get("Low",      0),
            severity_counts.get("Info",     0),
        )

        return {
            "statusCode":      200,
            "scan_timestamp":  scan_time,
            "aws_account_id":  account_id,
            "total_findings":  len(new_findings),
            "severity_counts": severity_counts,
            "s3_json_key":     s3_keys.get("json_key"),
            "s3_text_key":     s3_keys.get("text_key"),
        }

    except Exception as exc:
        logger.exception("Lambda scan failed: %s", exc)
        return {
            "statusCode":      500,
            "error":           str(exc),
            "scan_timestamp":  scan_time,
            "aws_account_id":  account_id,
        }
