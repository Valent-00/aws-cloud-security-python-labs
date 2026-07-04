"""
send_test_notification.py
==========================
Manual smoke test — actually sends a real Slack/Teams message using
whichever of SLACK_WEBHOOK_URL / TEAMS_WEBHOOK_URL is set in your
environment, with a fake (clearly-labelled) Critical finding.

This is NOT part of the pytest suite. tests/test_notifications.py
already proves the logic works with every HTTP call mocked — this
script is for the one thing that can't be mocked: confirming a real
webhook URL actually delivers to a real channel.

Run with: python send_test_notification.py
"""
import logging
import os

from notifications.notifications import notify_if_critical_or_high

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

slack_set = bool(os.getenv("SLACK_WEBHOOK_URL"))
teams_set = bool(os.getenv("TEAMS_WEBHOOK_URL"))

if not slack_set and not teams_set:
    print("Neither SLACK_WEBHOOK_URL nor TEAMS_WEBHOOK_URL is set.")
    print("Set at least one first, e.g. in PowerShell:")
    print('  $env:SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/..."')
    print('  $env:TEAMS_WEBHOOK_URL = "https://....powerautomate.com/..."')
    raise SystemExit(1)

print(f"SLACK_WEBHOOK_URL set: {slack_set}")
print(f"TEAMS_WEBHOOK_URL set: {teams_set}")
print()

fake_findings = [
    {"username": "test-user", "alert_type": "Test Notification",
     "severity": "Critical", "risk_score": 99},
]
fake_severity_counts = {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

print("Sending...")
result = notify_if_critical_or_high(
    findings=fake_findings,
    severity_counts=fake_severity_counts,
    scan_timestamp="THIS IS A MANUAL TEST — not a real scan",
    dashboard_url=os.getenv("DASHBOARD_URL") or None,
)
print()
print(f"Result: {result}")
print()

for channel in ("slack", "teams"):
    status = result[channel]
    if status is True:
        print(f"✅ {channel.capitalize()}: sent — go check your channel now.")
    elif status is False:
        print(f"❌ {channel.capitalize()}: webhook URL was set but the send FAILED "
              f"— see the ERROR line logged above for why.")
    else:
        print(f"⏭️  {channel.capitalize()}: URL not set, skipped (this is fine if "
              f"you're only testing one platform right now).")