"""
cloudtrail_inventory.py
========================
Real AWS CloudTrail event analysis — the piece that actually matches
the project title ("...CloudTrail Log Analysis and Incident Explanation
System"). boto3_inventory.py answers "what does IAM look like right
now" (a state snapshot); this module answers "what actually happened,
and why does this finding exist" by pulling and parsing the real
CloudTrail events around a specific finding.

This is the same investigation done by hand for a Critical "Root
Account Used" finding: a borderline CloudTrail CLI lookup, then reading
sourceIPAddress / MFAUsed / userAgent out of the raw event to decide
whether it was legitimate. This module automates exactly that.

Two-step usage
--------------
1. fetch_events_for_principal(...) — pulls and parses real CloudTrail
   events for a user/time window into clean, stable-schema dicts.
2. build_incident_narrative_context(...) — combines those events with
   a Finding into a structured text block, ready to drop into an LLM
   prompt for the "Incident Explanation" half of the project.

This module does NOT call any LLM itself — that needs your existing
Ollama/report-generation code, which this hasn't seen yet. Step 2
prepares clean context; wiring it into an actual prompt is the next
piece once this is reviewed.

AWS IAM/CloudTrail permissions required (add to iam_execution_role.json
if this gets called from Lambda; FastAPI-side calls need the same on
whatever credentials that process uses)
-------------------------------------------------------------------
  cloudtrail:LookupEvents

Region note
-----------
Root-user console sign-in events are ALWAYS recorded in us-east-1,
regardless of which region the account's resources actually live in —
documented AWS behavior, not a bug (confirmed against this project's
own account: a root login showed up there, not in ap-southeast-2).
IAM-user console logins are less consistent — they can land in
us-east-1 OR a region-specific endpoint depending on browser cookie
state at sign-in time. Default here is us-east-1 since that's the
reliable case; if an IAM-user lookup comes back empty, the event may
be in a different region (future enhancement: fan out to multiple
regions when a single-region lookup misses).
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("iam_scanner.cloudtrail")

DEFAULT_REGION = "us-east-1"


# ===========================================================================
# Internal helpers
# ===========================================================================

def _parse_event(event: dict) -> dict[str, Any]:
    """
    Parse one raw CloudTrail lookup_events record into a clean,
    stable-schema dict, pulling out the fields that matter for
    incident explanation regardless of event type.

    Args:
        event: One item from lookup_events' "Events" list (the
               CloudTrailEvent field is a JSON string, not yet parsed).

    Returns:
        {
          "event_name":   str,
          "event_time":   ISO-8601 str,
          "source_ip":    str,
          "user_agent":   str,
          "aws_region":   str,
          "event_source": str,           # e.g. "signin.amazonaws.com"
          "mfa_used":     bool | None,   # only meaningful for sign-ins
          "success":      bool | None,   # only meaningful for sign-ins
          "raw":          dict,          # full parsed CloudTrail event
        }

    Time  : O(1)   Space: O(1)
    """
    raw = json.loads(event["CloudTrailEvent"])
    additional = raw.get("additionalEventData", {}) or {}
    response = raw.get("responseElements", {}) or {}

    mfa_used = None
    if "MFAUsed" in additional:
        mfa_used = additional.get("MFAUsed") == "Yes"

    success = None
    if isinstance(response, dict) and "ConsoleLogin" in response:
        success = response.get("ConsoleLogin") == "Success"

    return {
        "event_name":   raw.get("eventName", event.get("EventName", "")),
        "event_time":   raw.get("eventTime", ""),
        "source_ip":    raw.get("sourceIPAddress", ""),
        "user_agent":   raw.get("userAgent", ""),
        "aws_region":   raw.get("awsRegion", ""),
        "event_source": raw.get("eventSource", ""),
        "mfa_used":     mfa_used,
        "success":      success,
        "raw":          raw,
    }


# ===========================================================================
# Public API
# ===========================================================================

def fetch_events_for_principal(
    username: str,
    around: datetime,
    window_minutes: int = 60,
    event_names: list[str] | None = None,
    region: str = DEFAULT_REGION,
) -> list[dict[str, Any]]:
    """
    Fetch and parse real CloudTrail events for one IAM principal around
    a specific point in time.

    Args:
        username:       IAM username, or "root" for the root account.
        around:         Timestamp to search around — typically a
                        Finding's scan_timestamp.
        window_minutes: Minutes before AND after `around` to search
                        (default 60 — generous enough to absorb a few
                        seconds to minutes of CloudTrail delivery lag).
        event_names:    Optional filter to specific event types (e.g.
                        ["ConsoleLogin"]). None = all events found for
                        this principal in the window.
        region:         AWS region to query. See module docstring's
                        "Region note" — defaults to us-east-1.

    Returns:
        List of structured event dicts (see _parse_event), sorted
        oldest-first. Empty list on any AWS API error — callers should
        treat that as "couldn't confirm," not "nothing happened."

    Time  : O(e) where e = events found in window   Space: O(e)
    """
    client = boto3.client("cloudtrail", region_name=region)
    start_time = around - timedelta(minutes=window_minutes)
    end_time = around + timedelta(minutes=window_minutes)

    lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": username}]

    results: list[dict[str, Any]] = []
    try:
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=lookup_attrs,
            StartTime=start_time,
            EndTime=end_time,
        ):
            for event in page.get("Events", []):
                parsed = _parse_event(event)
                if event_names and parsed["event_name"] not in event_names:
                    continue
                results.append(parsed)
    except ClientError as exc:
        logger.error("CloudTrail lookup_events failed for %s: %s", username, exc)
        return []

    results.sort(key=lambda e: e["event_time"])
    return results


def build_incident_narrative_context(
    finding: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    """
    Combine a Finding with its surrounding CloudTrail events into a
    structured text block — clean context for an LLM prompt, not the
    explanation itself. Keeping this separate from any prompt-building
    code means the LLM prompt is built from a few clear facts rather
    than a raw, noisy CloudTrail record.

    Args:
        finding: A Finding.to_dict() (or equivalent) — expected to
                 include 'username', 'alert_type', 'detail', 'severity'.
        events:  Output of fetch_events_for_principal() for this finding.

    Returns:
        Plain-text context block.

    Time  : O(e)   Space: O(e)
    """
    lines = [
        f"FINDING: {finding.get('alert_type', '')} ({finding.get('severity', '')})",
        f"User: {finding.get('username', '')}",
        f"Detail: {finding.get('detail', '')}",
        "",
        f"CLOUDTRAIL EVENTS AROUND THIS FINDING ({len(events)} found):",
    ]
    if not events:
        lines.append("  (No matching CloudTrail events found in the search window.)")
    for e in events:
        mfa_note = ""
        if e["mfa_used"] is not None:
            mfa_note = f", MFA used: {'Yes' if e['mfa_used'] else 'No'}"
        lines.append(
            f"  - {e['event_time']}: {e['event_name']} "
            f"from {e['source_ip']}{mfa_note}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    # Quick manual test against your REAL AWS account — no mocking.
    # Usage:
    #   python cloudtrail_inventory.py root
    #   python cloudtrail_inventory.py valent-admin
    import sys

    from datetime import timezone

    username = sys.argv[1] if len(sys.argv) > 1 else "root"
    print(f"Searching CloudTrail for '{username}' in the last 24 hours "
          f"(region={DEFAULT_REGION})...\n")

    events = fetch_events_for_principal(
        username,
        datetime.now(timezone.utc),
        window_minutes=24 * 60,
    )

    if not events:
        print("No events found. If this is an IAM user (not root), the "
              "event may have landed in a different region — see the "
              "module docstring's 'Region note'.")
    else:
        print(f"Found {len(events)} event(s):\n")
        for e in events:
            mfa_note = ""
            if e["mfa_used"] is not None:
                mfa_note = f"  MFA used: {'Yes' if e['mfa_used'] else 'No'}"
            print(f"  {e['event_time']}  {e['event_name']:<20} "
                  f"from {e['source_ip']}{mfa_note}")