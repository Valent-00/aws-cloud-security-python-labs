"""
test_main_routes.py
====================
Integration tests for main.py's FastAPI routes, using TestClient against
a real in-memory SQLite DB (see conftest.py) — not mocked. The `client`
fixture bypasses auth via dependency override for testing route logic;
`client_real_auth` leaves auth untouched, for verifying it's actually
enforced.
"""
from datetime import datetime, timezone

import pytest

from auth.auth import hash_password
from models.database import AnalystUser, FindingRecord, ScanRun, utc_now


# ===========================================================================
# Health
# ===========================================================================

def test_health_check_requires_no_auth(client_real_auth):
    response = client_real_auth.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ===========================================================================
# Auth enforcement — using client_real_auth (auth NOT bypassed)
# ===========================================================================

class TestAuthIsActuallyEnforced:
    def test_protected_route_rejects_request_with_no_token(self, client_real_auth):
        response = client_real_auth.get("/api/v1/dashboard")
        assert response.status_code == 401

    def test_protected_route_rejects_garbage_token(self, client_real_auth):
        # Fix #1: auth reads the httpOnly cookie, not an Authorization
        # header — so the garbage token goes in the cookie.
        client_real_auth.cookies.set("iam_scanner_token", "not-a-real-token")
        response = client_real_auth.get("/api/v1/dashboard")
        assert response.status_code == 401

    def test_protected_route_accepts_valid_session_cookie(self, client_real_auth, db_session):
        user = AnalystUser(
            username="real-token-user",
            hashed_password=hash_password("pw"),
            role="analyst", is_active=True, created_at=utc_now(),
        )
        db_session.add(user)
        db_session.commit()

        login_resp = client_real_auth.post(
            "/api/v1/auth/login",
            json={"username": "real-token-user", "password": "pw"},
        )
        assert login_resp.status_code == 200

        # Fix #1: the TestClient stores the Set-Cookie from login and
        # sends it automatically — exactly what a real browser does.
        response = client_real_auth.get("/api/v1/dashboard")
        assert response.status_code == 200


# ===========================================================================
# Login — real bcrypt + real JWT, no mocking
# ===========================================================================

class TestLogin:
    def test_correct_credentials_set_httponly_cookie_not_body_token(
        self, client_real_auth, db_session
    ):
        user = AnalystUser(
            username="alice", hashed_password=hash_password("hunter2"),
            role="analyst", is_active=True, created_at=utc_now(),
        )
        db_session.add(user)
        db_session.commit()

        response = client_real_auth.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "hunter2"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["username"] == "alice"
        assert body["role"] == "analyst"

        # Fix #1: the JWT must travel ONLY in the httpOnly Set-Cookie
        # header — never in a JSON body that XSS could read.
        assert "access_token" not in body
        set_cookie = response.headers.get("set-cookie", "")
        assert "iam_scanner_token=" in set_cookie
        assert "HttpOnly" in set_cookie

    def test_wrong_password_returns_401(self, client_real_auth, db_session):
        user = AnalystUser(
            username="alice", hashed_password=hash_password("hunter2"),
            role="analyst", is_active=True, created_at=utc_now(),
        )
        db_session.add(user)
        db_session.commit()

        response = client_real_auth.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "wrong"}
        )
        assert response.status_code == 401

    def test_unknown_username_returns_same_401_as_wrong_password(self, client_real_auth):
        """Enumeration-safety check: a nonexistent username and a wrong
        password must be indistinguishable to the caller."""
        response = client_real_auth.post(
            "/api/v1/auth/login",
            json={"username": "does-not-exist", "password": "anything"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password."

    def test_deactivated_account_cannot_log_in(self, client_real_auth, db_session):
        user = AnalystUser(
            username="fired-analyst", hashed_password=hash_password("hunter2"),
            role="analyst", is_active=False, created_at=utc_now(),
        )
        db_session.add(user)
        db_session.commit()

        response = client_real_auth.post(
            "/api/v1/auth/login",
            json={"username": "fired-analyst", "password": "hunter2"},
        )
        assert response.status_code == 401

    def test_whitespace_padded_password_is_stripped(self, client_real_auth, db_session):
        """Regression test for the exact PowerShell-quoting bug found
        earlier: a trailing space baked into a password at account
        creation should not make login impossible."""
        user = AnalystUser(
            username="alice", hashed_password=hash_password("hunter2"),
            role="analyst", is_active=True, created_at=utc_now(),
        )
        db_session.add(user)
        db_session.commit()

        response = client_real_auth.post(
            "/api/v1/auth/login",
            json={"username": "alice  ", "password": "hunter2  "},
        )
        assert response.status_code == 200


# ===========================================================================
# Dashboard
# ===========================================================================

class TestDashboard:
    def test_returns_zeroed_counts_when_no_scans_exist(self, client):
        response = client.get("/api/v1/dashboard")
        assert response.status_code == 200
        body = response.json()
        assert body["total_scans_run"] == 0
        assert body["critical_count"] == 0

    def test_reflects_most_recent_completed_scan(self, client, db_session):
        db_session.add(ScanRun(
            started_at=utc_now(), completed_at=utc_now(), status="completed",
            total_findings=5, critical_count=2, high_count=1,
            medium_count=2, low_count=0, info_count=0,
        ))
        db_session.commit()

        response = client.get("/api/v1/dashboard")
        body = response.json()
        assert body["critical_count"] == 2
        assert body["total_findings"] == 5
        assert body["total_scans_run"] == 1

    def test_ignores_pending_scan_uses_last_completed(self, client, db_session):
        db_session.add(ScanRun(
            started_at=utc_now(), status="completed",
            critical_count=1, total_findings=1,
        ))
        db_session.add(ScanRun(started_at=utc_now(), status="pending"))
        db_session.commit()

        response = client.get("/api/v1/dashboard")
        body = response.json()
        assert body["critical_count"] == 1
        assert body["total_scans_run"] == 2  # both scans counted in total


# ===========================================================================
# Scans
# ===========================================================================

class TestScans:
    def test_list_scans_returns_newest_first(self, client, db_session):
        db_session.add(ScanRun(started_at="2026-06-25T00:00:00Z", status="completed"))
        db_session.add(ScanRun(started_at="2026-06-26T00:00:00Z", status="completed"))
        db_session.commit()

        response = client.get("/api/v1/scans")
        body = response.json()
        assert body[0]["started_at"] == "2026-06-26T00:00:00Z"

    def test_get_scan_status_404_for_unknown_id(self, client):
        response = client.get("/api/v1/scans/9999/status")
        assert response.status_code == 404

    def test_get_scan_findings_filters_by_severity(self, client, db_session):
        scan = ScanRun(started_at=utc_now(), status="completed")
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="X",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1",
        ))
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="alice", alert_type="Y",
            severity="Low", risk_score=10, detail="d", sla="72h",
            fingerprint="fp2",
        ))
        db_session.commit()

        response = client.get(f"/api/v1/scans/{scan.id}/findings?severity=Critical")
        body = response.json()
        assert len(body) == 1
        assert body[0]["severity"] == "Critical"

    def test_get_scan_findings_404_for_unknown_scan(self, client):
        response = client.get("/api/v1/scans/9999/findings")
        assert response.status_code == 404


# ===========================================================================
# Users — regression test for the documented N+1 fix
# ===========================================================================

class TestListUsers:
    def test_groups_findings_by_user_with_correct_counts_and_worst_severity(
        self, client, db_session
    ):
        """
        Regression test for the bug fix documented in main.py's own
        docstring: list_users replaced an N+1 query pattern with a
        single GROUP BY. This verifies the grouped counts and the
        per-user "worst severity" are actually correct, not just that
        the query runs without error.
        """
        scan = ScanRun(started_at=utc_now(), status="completed")
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="A",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1", acknowledged=False,
        ))
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="B",
            severity="Medium", risk_score=50, detail="d", sla="24h",
            fingerprint="fp2", acknowledged=True,
        ))
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="valent-admin", alert_type="C",
            severity="High", risk_score=75, detail="d", sla="4h",
            fingerprint="fp3", acknowledged=False,
        ))
        db_session.commit()

        response = client.get("/api/v1/users")
        body = response.json()
        by_username = {u["username"]: u for u in body}

        assert by_username["root"]["finding_count"] == 2
        assert by_username["root"]["highest_severity"] == "Critical"
        assert by_username["root"]["acknowledged"] == 1
        assert by_username["root"]["unacknowledged"] == 1
        assert by_username["valent-admin"]["highest_severity"] == "High"

        # Critical user (root) must sort before High user (valent-admin)
        assert body[0]["username"] == "root"

    def test_get_user_findings_404_when_user_has_none(self, client):
        response = client.get("/api/v1/users/nobody/findings")
        assert response.status_code == 404


# ===========================================================================
# Acknowledge / un-acknowledge
# ===========================================================================

class TestAcknowledge:
    def _make_finding(self, db_session) -> FindingRecord:
        scan = ScanRun(started_at=utc_now(), status="completed")
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)

        finding = FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="X",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1",
        )
        db_session.add(finding)
        db_session.commit()
        db_session.refresh(finding)
        return finding

    def test_acknowledge_sets_fields_and_records_who(self, client, db_session, fake_analyst_user):
        finding = self._make_finding(db_session)

        response = client.patch(
            f"/api/v1/findings/{finding.id}/acknowledge",
            json={"note": "Confirmed legitimate — MFA-protected login."},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["acknowledged"] is True
        assert body["acknowledged_by"] == fake_analyst_user.username
        assert "MFA-protected" in body["ack_note"]

    def test_unacknowledge_clears_fields(self, client, db_session):
        finding = self._make_finding(db_session)
        client.patch(f"/api/v1/findings/{finding.id}/acknowledge", json={})

        response = client.delete(f"/api/v1/findings/{finding.id}/acknowledge")
        assert response.status_code == 200
        body = response.json()
        assert body["acknowledged"] is False
        assert body["acknowledged_by"] is None

    def test_acknowledge_404_for_unknown_finding(self, client):
        response = client.patch(
            "/api/v1/findings/9999/acknowledge", json={"note": "x"}
        )
        assert response.status_code == 404