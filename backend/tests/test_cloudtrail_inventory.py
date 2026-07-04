"""
test_cloudtrail_inventory.py
=============================
Tests for cloudtrail_inventory.py — the real CloudTrail event fetcher
and parser built to back the AI Evidence Analysis Engine.

Every test mocks boto3; nothing makes a real AWS call.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import cloud.cloudtrail_inventory as ct


# ===========================================================================
# _parse_event
# ===========================================================================

class TestParseEvent:
    def test_parses_real_root_login_event_correctly(self, real_root_login_event):
        """Pinned to the actual event pulled from a real account during
        this project's own root-login investigation."""
        parsed = ct._parse_event(real_root_login_event)

        assert parsed["event_name"] == "ConsoleLogin"
        assert parsed["event_time"] == "2026-06-26T06:50:58Z"
        assert parsed["source_ip"] == "115.164.36.147"
        assert parsed["mfa_used"] is True
        assert parsed["success"] is True
        assert parsed["raw"]["userIdentity"]["type"] == "Root"

    def test_mfa_used_is_none_when_not_a_signin_event(self):
        """Non-signin events (e.g. CreateUser) have no MFAUsed field —
        this must come back as None, not False, since None means
        'not applicable' and False would incorrectly imply a sign-in
        happened without MFA."""
        event = {
            "CloudTrailEvent": (
                '{"eventName":"CreateUser","eventTime":"2026-06-25T08:11:00Z",'
                '"sourceIPAddress":"115.164.36.147","userAgent":"aws-cli/2.0",'
                '"additionalEventData":{}}'
            )
        }
        parsed = ct._parse_event(event)
        assert parsed["mfa_used"] is None
        assert parsed["success"] is None

    def test_includes_region_and_event_source(self):
        """Required for the 'Region'/'Service' columns the incident
        explanation prompt expects — these must be top-level keys, not
        buried only inside 'raw'."""
        event = {
            "CloudTrailEvent": (
                '{"eventName":"ConsoleLogin","eventTime":"2026-06-26T06:50:58Z",'
                '"awsRegion":"us-east-1","eventSource":"signin.amazonaws.com",'
                '"sourceIPAddress":"1.2.3.4","userAgent":"test"}'
            )
        }
        parsed = ct._parse_event(event)
        assert parsed["aws_region"] == "us-east-1"
        assert parsed["event_source"] == "signin.amazonaws.com"


# ===========================================================================
# fetch_events_for_principal
# ===========================================================================

class TestFetchEventsForPrincipal:
    def test_returns_parsed_events_sorted_oldest_first(self, real_root_login_event):
        older_event = {
            "CloudTrailEvent": (
                '{"eventName":"ConsoleLogin","eventTime":"2026-06-25T08:09:42Z",'
                '"sourceIPAddress":"115.164.36.147","userAgent":"test",'
                '"additionalEventData":{"MFAUsed":"No"},'
                '"responseElements":{"ConsoleLogin":"Success"}}'
            )
        }
        fake_client = MagicMock()
        fake_paginator = MagicMock()
        # Deliberately return newer event first to prove sorting works
        fake_paginator.paginate.return_value = [
            {"Events": [real_root_login_event, older_event]}
        ]
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            events = ct.fetch_events_for_principal(
                "root", datetime(2026, 6, 26, 7, 0, tzinfo=timezone.utc)
            )

        assert len(events) == 2
        assert events[0]["event_time"] == "2026-06-25T08:09:42Z"
        assert events[1]["event_time"] == "2026-06-26T06:50:58Z"

    def test_event_names_filter_excludes_non_matching_events(self, real_root_login_event):
        other_event = {
            "CloudTrailEvent": (
                '{"eventName":"CreateAccessKey","eventTime":"2026-06-26T06:51:00Z",'
                '"sourceIPAddress":"115.164.36.147","userAgent":"test"}'
            )
        }
        fake_client = MagicMock()
        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = [
            {"Events": [real_root_login_event, other_event]}
        ]
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            events = ct.fetch_events_for_principal(
                "root",
                datetime(2026, 6, 26, 7, 0, tzinfo=timezone.utc),
                event_names=["ConsoleLogin"],
            )

        assert len(events) == 1
        assert events[0]["event_name"] == "ConsoleLogin"

    def test_returns_empty_list_on_client_error_not_an_exception(self):
        """A failed lookup_events call (e.g. denied permission) should
        degrade to an empty list — callers already treat 'no events
        found' as 'cannot confirm', this must not crash the caller."""
        from botocore.exceptions import ClientError

        fake_client = MagicMock()
        fake_paginator = MagicMock()
        fake_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "LookupEvents",
        )
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            events = ct.fetch_events_for_principal(
                "root", datetime.now(timezone.utc)
            )
        assert events == []


# ===========================================================================
# build_incident_narrative_context
# ===========================================================================

class TestBuildIncidentNarrativeContext:
    def test_includes_mfa_status_when_present(self):
        finding = {
            "username": "root", "alert_type": "Root Account Used",
            "detail": "Root logged in.", "severity": "Critical",
        }
        events = [{
            "event_time": "2026-06-26T06:50:58Z", "event_name": "ConsoleLogin",
            "source_ip": "115.164.36.147", "mfa_used": True,
        }]
        context = ct.build_incident_narrative_context(finding, events)
        assert "MFA used: Yes" in context
        assert "Root Account Used" in context

    def test_notes_explicitly_when_no_events_found(self):
        finding = {"username": "root", "alert_type": "X", "detail": "", "severity": "Critical"}
        context = ct.build_incident_narrative_context(finding, [])
        assert "No matching CloudTrail events" in context