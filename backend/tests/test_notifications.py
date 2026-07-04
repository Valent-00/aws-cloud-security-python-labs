"""
test_notifications.py
======================
Tests for notifications.py — Slack/Teams message building, sending,
and the "only notify on Critical/High" gating logic. All HTTP calls
mocked; nothing posts to a real webhook.
"""
import os
from unittest.mock import MagicMock, patch

import requests

from shared import notifications as nt


SAMPLE_FINDINGS = [
    {"username": "root", "alert_type": "Root Account Used",
     "severity": "Critical", "risk_score": 99},
    {"username": "valent-admin", "alert_type": "MFA Disabled",
     "severity": "High", "risk_score": 75},
]


# ===========================================================================
# Message builders
# ===========================================================================

class TestBuildSlackMessage:
    def test_includes_severity_counts_in_header(self):
        msg = nt.build_slack_message(
            {"Critical": 2, "High": 1}, SAMPLE_FINDINGS, "2026-06-26T06:31:41Z"
        )
        header_text = msg["blocks"][0]["text"]["text"]
        assert "2 Critical" in header_text
        assert "1 High" in header_text

    def test_includes_dashboard_link_when_provided(self):
        msg = nt.build_slack_message(
            {"Critical": 1}, [], "2026-06-26T06:31:41Z",
            dashboard_url="https://dashboard.example.com",
        )
        body_text = msg["blocks"][1]["text"]["text"]
        assert "https://dashboard.example.com" in body_text

    def test_omits_dashboard_link_when_not_provided(self):
        msg = nt.build_slack_message({"Critical": 1}, [], "2026-06-26T06:31:41Z")
        body_text = msg["blocks"][1]["text"]["text"]
        assert "dashboard" not in body_text.lower()


class TestBuildTeamsMessage:
    def test_is_a_valid_messagecard_shape(self):
        msg = nt.build_teams_message(
            {"Critical": 2, "High": 1}, SAMPLE_FINDINGS, "2026-06-26T06:31:41Z"
        )
        assert msg["@type"] == "MessageCard"
        assert "Critical" in msg["title"]

    def test_theme_color_is_red_for_critical(self):
        msg = nt.build_teams_message({"Critical": 1, "High": 0}, [], "t")
        assert msg["themeColor"] == "D32F2F"

    def test_theme_color_is_orange_when_high_only(self):
        msg = nt.build_teams_message({"Critical": 0, "High": 1}, [], "t")
        assert msg["themeColor"] == "F57C00"

    def test_includes_open_uri_action_when_dashboard_url_given(self):
        msg = nt.build_teams_message(
            {"Critical": 1}, [], "t", dashboard_url="https://dashboard.example.com"
        )
        assert msg["potentialAction"][0]["targets"][0]["uri"] == "https://dashboard.example.com"


# ===========================================================================
# Senders
# ===========================================================================

class TestSendSlackNotification:
    def test_returns_true_on_success(self):
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        with patch("shared.notifications.requests.post", return_value=fake_response):
            assert nt.send_slack_notification("https://hooks.slack.com/x", {}) is True

    def test_returns_false_and_does_not_raise_on_failure(self):
        with patch(
            "shared.notifications.requests.post",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            assert nt.send_slack_notification("https://hooks.slack.com/x", {}) is False


class TestSendTeamsNotification:
    def test_returns_false_on_http_error(self):
        fake_response = MagicMock()
        fake_response.raise_for_status.side_effect = requests.exceptions.HTTPError()
        with patch("shared.notifications.requests.post", return_value=fake_response):
            assert nt.send_teams_notification("https://x.powerautomate.com/y", {}) is False


# ===========================================================================
# notify_if_critical_or_high — the gating + orchestration logic
# ===========================================================================

class TestNotifyIfCriticalOrHigh:
    def test_skips_entirely_when_no_critical_or_high(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://x.powerautomate.com/y")
        with patch("shared.notifications.send_slack_notification") as mock_slack, \
             patch("shared.notifications.send_teams_notification") as mock_teams:
            result = nt.notify_if_critical_or_high(
                [], {"Critical": 0, "High": 0, "Medium": 5}, "t"
            )
        mock_slack.assert_not_called()
        mock_teams.assert_not_called()
        assert result == {"slack": None, "teams": None}

    def test_sends_to_both_when_both_configured_and_critical_exists(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://x.powerautomate.com/y")
        with patch("shared.notifications.send_slack_notification", return_value=True) as mock_slack, \
             patch("shared.notifications.send_teams_notification", return_value=True) as mock_teams:
            result = nt.notify_if_critical_or_high(
                SAMPLE_FINDINGS, {"Critical": 1, "High": 0}, "t"
            )
        mock_slack.assert_called_once()
        mock_teams.assert_called_once()
        assert result == {"slack": True, "teams": True}

    def test_high_alone_also_triggers_notification(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
        with patch("shared.notifications.send_slack_notification", return_value=True) as mock_slack:
            nt.notify_if_critical_or_high([], {"Critical": 0, "High": 1}, "t")
        mock_slack.assert_called_once()

    def test_skips_slack_when_not_configured_but_still_sends_teams(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://x.powerautomate.com/y")
        with patch("shared.notifications.send_teams_notification", return_value=True) as mock_teams:
            result = nt.notify_if_critical_or_high(
                SAMPLE_FINDINGS, {"Critical": 1, "High": 0}, "t"
            )
        assert result["slack"] is None
        assert result["teams"] is True
        mock_teams.assert_called_once()

    def test_neither_configured_returns_both_none_without_error(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
        result = nt.notify_if_critical_or_high(
            SAMPLE_FINDINGS, {"Critical": 1, "High": 0}, "t"
        )
        assert result == {"slack": None, "teams": None}
