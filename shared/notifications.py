"""
notifications.py
=================
Real-time Slack / Microsoft Teams alerting when a scan finds Critical
or High severity issues — automating the exact "check CloudTrail,
decide if it's bad" workflow done by hand earlier tonight, except now
someone gets pinged immediately instead of finding out next time they
open the dashboard.

Microsoft Teams note (current as of mid-2026)
-----------------------------------------------
Classic Teams "Incoming Webhook" connectors (webhook.office.com URLs,
via Office 365 Connectors) were fully retired in Microsoft's May 2026
rollout — those URLs no longer work. The replacement is a Teams
*Workflows* webhook (Power Automate-backed): in Teams, go to a
channel -> Workflows -> search "webhook" -> use the "Post to a channel
when a webhook request is received" template. That gives you a
different-looking URL (powerautomate.com / flow.microsoft.com) to use
as TEAMS_WEBHOOK_URL below. Workflows webhooks support posting the
classic MessageCard JSON format directly (no Adaptive Card conversion
needed) as long as you don't need interactive buttons — which a
security alert doesn't, so this module uses MessageCard for simplicity.

Slack is unaffected by any of this — Incoming Webhooks (the
hooks.slack.com URL from a Slack App's "Incoming Webhooks" feature)
work exactly as they always have.

Security fix — HTTPS enforcement on webhook URLs (Fix H-2, 2026-07)
-------------------------------------------------------------------
The webhook URL is itself a secret (anyone holding it can post to your
channel), and the payloads this module sends contain real security
telemetry — affected usernames, alert types, and risk scores. Sending
any of that to a plaintext http:// URL would expose both the secret and
the finding details to anyone able to observe the network path
(MITRE T1040 / T1557).

Both senders now refuse to POST to any URL whose scheme is not https,
BEFORE the request is made. The check lives at the point of use (inside
each sender) so no caller — present or future — can bypass it. It fails
closed (nothing is sent) but soft (returns False and logs), preserving
this module's hard contract that a notification failure NEVER raises
into, and therefore never fails, the scan that triggered it. There is
no legitimate http:// Slack or Teams webhook, so this rejects http even
against localhost — a deliberate trade-off, not an oversight.

Configuration
-------------
  SLACK_WEBHOOK_URL   Optional. If unset, Slack notifications are skipped.
  TEAMS_WEBHOOK_URL   Optional. If unset, Teams notifications are skipped.
  DASHBOARD_URL        Optional. If set, included as a link in both messages.

Both webhook URLs are secrets — anyone who has one can post messages to
that channel. Never commit them; set via environment variable only,
same as every other secret in this project. They MUST be https:// URLs.
"""
import logging
import os
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("iam_scanner.notifications")

_NOTIFY_SEVERITIES = ("Critical", "High")
_REQUEST_TIMEOUT_SEC = 10


# ===========================================================================
# URL safety — Fix H-2
# ===========================================================================

def _is_https_webhook_url(url: str) -> bool:
    """
    Return True only if `url` is a well-formed https:// URL.

    Scheme comparison is case-insensitive (RFC 3986 §3.1 — schemes are
    case-insensitive, so "HTTPS://..." is valid and must not be wrongly
    rejected). Empty, whitespace-only, or malformed URLs — anything
    urlparse can't extract an https scheme and a host from — are treated
    as unsafe rather than raising.

    Args:
        url: The webhook URL read from the environment.

    Returns:
        True if the URL uses https and has a network location, else False.
    """
    try:
        parsed = urlparse(url.strip())
    except (ValueError, AttributeError):
        return False
    return parsed.scheme.lower() == "https" and bool(parsed.netloc)


# ===========================================================================
# Message builders
# ===========================================================================

def _top_findings_text(findings: list[dict], limit: int = 5) -> list[str]:
    """Format up to `limit` of the highest-risk findings as short lines,
    shared by both Slack and Teams builders so the two channels never
    drift out of sync on what counts as "the top findings"."""
    sorted_findings = sorted(
        findings, key=lambda f: f.get("risk_score", 0), reverse=True
    )
    lines = []
    for f in sorted_findings[:limit]:
        lines.append(
            f"[{f.get('severity', '?')}] {f.get('username', '?')} — "
            f"{f.get('alert_type', '?')} (score {f.get('risk_score', '?')})"
        )
    return lines


def build_slack_message(
    severity_counts: dict[str, int],
    findings: list[dict],
    scan_timestamp: str,
    dashboard_url: str | None = None,
) -> dict[str, Any]:
    """
    Build a Slack Block Kit payload for POSTing to an Incoming Webhook.

    Args:
        severity_counts: e.g. {"Critical": 2, "High": 1, "Medium": 2, ...}
        findings:        Finding dicts (Finding.to_dict() shape) for
                          this scan — used to surface the top few by
                          risk score, not the full list.
        scan_timestamp:  ISO-8601 timestamp of the scan that triggered this.
        dashboard_url:   Optional link back to the dashboard.

    Returns:
        JSON-serialisable dict ready for requests.post(..., json=this).
    """
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)

    header = f"🚨 IAM Security Scanner: {critical} Critical, {high} High finding(s)"
    lines = [f"*Scan time:* {scan_timestamp}"]
    lines.extend(_top_findings_text(findings))
    if dashboard_url:
        lines.append(f"<{dashboard_url}|Open dashboard>")

    return {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        ]
    }


def build_teams_message(
    severity_counts: dict[str, int],
    findings: list[dict],
    scan_timestamp: str,
    dashboard_url: str | None = None,
) -> dict[str, Any]:
    """
    Build a MessageCard payload for POSTing to a Teams Workflows webhook.

    Args/Returns: same shape as build_slack_message(), different format.
    """
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    title = f"IAM Security Scanner: {critical} Critical, {high} High finding(s)"

    facts = [{"name": sev, "value": str(severity_counts.get(sev, 0))}
             for sev in ("Critical", "High", "Medium", "Low", "Info")]

    text_lines = [f"**Scan time:** {scan_timestamp}", ""]
    text_lines.extend(_top_findings_text(findings))

    card: dict[str, Any] = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": "D32F2F" if critical else "F57C00",
        "title": title,
        "sections": [{"facts": facts, "text": "\n\n".join(text_lines)}],
    }
    if dashboard_url:
        card["potentialAction"] = [{
            "@type": "OpenUri",
            "name": "Open dashboard",
            "targets": [{"os": "default", "uri": dashboard_url}],
        }]
    return card


# ===========================================================================
# Senders — each degrades to False on failure, never raises
# ===========================================================================

def send_slack_notification(webhook_url: str, payload: dict[str, Any]) -> bool:
    """POST a built Slack payload to an Incoming Webhook URL.

    Fix H-2: refuses to send to any non-https URL before making the
    request — the webhook secret and finding details must never travel
    in plaintext.

    Returns:
        True if Slack accepted it (HTTP 200), False on any failure
        (including a rejected non-https URL) — never raises. A failed
        notification must never be allowed to fail the scan that
        triggered it.
    """
    if not _is_https_webhook_url(webhook_url):
        logger.error(
            "Refusing to send Slack notification: SLACK_WEBHOOK_URL is not a "
            "valid https:// URL. Webhook secrets and finding details must not "
            "be sent over plaintext http. Fix the URL and re-run."
        )
        return False
    try:
        response = requests.post(webhook_url, json=payload, timeout=_REQUEST_TIMEOUT_SEC)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        logger.error("Slack notification failed: %s", exc)
        return False


def send_teams_notification(webhook_url: str, payload: dict[str, Any]) -> bool:
    """POST a built Teams MessageCard payload to a Workflows webhook URL.

    Fix H-2: refuses to send to any non-https URL before making the
    request — same rationale as send_slack_notification.

    Returns:
        True on success, False on any failure (including a rejected
        non-https URL) — never raises.
    """
    if not _is_https_webhook_url(webhook_url):
        logger.error(
            "Refusing to send Teams notification: TEAMS_WEBHOOK_URL is not a "
            "valid https:// URL. Webhook secrets and finding details must not "
            "be sent over plaintext http. Fix the URL and re-run."
        )
        return False
    try:
        response = requests.post(webhook_url, json=payload, timeout=_REQUEST_TIMEOUT_SEC)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        logger.error("Teams notification failed: %s", exc)
        return False


# ===========================================================================
# Top-level orchestrator
# ===========================================================================

def notify_if_critical_or_high(
    findings: list[dict],
    severity_counts: dict[str, int],
    scan_timestamp: str,
    dashboard_url: str | None = None,
) -> dict[str, bool | None]:
    """
    Send Slack/Teams notifications if (and only if) this scan found at
    least one Critical or High finding. Reads SLACK_WEBHOOK_URL /
    TEAMS_WEBHOOK_URL from the environment; whichever isn't set is
    skipped, not treated as an error.

    Fix H-2: the https:// requirement is enforced inside the senders, so
    a plaintext URL here results in a logged refusal and a False result
    for that channel — it is never sent.

    Args:
        findings:        Finding dicts for this scan.
        severity_counts: This scan's severity counts.
        scan_timestamp:  ISO-8601 timestamp of this scan.
        dashboard_url:   Optional dashboard link to include.

    Returns:
        {"slack": True | False | None, "teams": True | False | None}
        — None means "not configured, skipped"; True/False is the
        actual send result. Never raises — callers should call this
        and move on regardless of the result.
    """
    result: dict[str, bool | None] = {"slack": None, "teams": None}

    should_notify = (
        severity_counts.get("Critical", 0) > 0
        or severity_counts.get("High", 0) > 0
    )
    if not should_notify:
        return result

    slack_url = os.getenv("SLACK_WEBHOOK_URL", "")
    if slack_url:
        payload = build_slack_message(severity_counts, findings, scan_timestamp, dashboard_url)
        result["slack"] = send_slack_notification(slack_url, payload)

    teams_url = os.getenv("TEAMS_WEBHOOK_URL", "")
    if teams_url:
        payload = build_teams_message(severity_counts, findings, scan_timestamp, dashboard_url)
        result["teams"] = send_teams_notification(teams_url, payload)

    return result