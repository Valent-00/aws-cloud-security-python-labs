"""
test_analytics_routes.py
=========================
Route-level tests for the four /api/v1/analytics endpoints in main.py.
The aggregation logic itself is already covered for real in
test_analytics.py — these verify the ROUTE wiring: auth enforcement,
query param plumbing (limit, scan_id), and response shape.
"""
from models.database import FindingRecord, ScanRun, utc_now


def _make_completed_scan(db_session, **overrides) -> ScanRun:
    defaults = dict(
        started_at=utc_now(), completed_at=utc_now(), status="completed",
        total_findings=1, critical_count=1, high_count=0,
        medium_count=0, low_count=0, info_count=0,
    )
    defaults.update(overrides)
    scan = ScanRun(**defaults)
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


class TestAnalyticsRoutesRequireAuth:
    def test_risk_trend_requires_auth(self, client_real_auth):
        assert client_real_auth.get("/api/v1/analytics/risk-trend").status_code == 401

    def test_mitre_coverage_requires_auth(self, client_real_auth):
        assert client_real_auth.get("/api/v1/analytics/mitre-coverage").status_code == 401

    def test_alert_type_breakdown_requires_auth(self, client_real_auth):
        assert client_real_auth.get("/api/v1/analytics/alert-type-breakdown").status_code == 401

    def test_scan_stats_requires_auth(self, client_real_auth):
        assert client_real_auth.get("/api/v1/analytics/scan-stats").status_code == 401


class TestRiskTrendRoute:
    def test_returns_trend_points(self, client, db_session):
        scan = _make_completed_scan(db_session)
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="X",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1",
        ))
        db_session.commit()

        response = client.get("/api/v1/analytics/risk-trend")
        assert response.status_code == 200
        body = response.json()
        assert body[0]["scan_id"] == scan.id
        assert body[0]["avg_risk_score"] == 99.0

    def test_limit_param_is_respected(self, client, db_session):
        for i in range(5):
            _make_completed_scan(db_session, started_at=f"2026-06-2{i}T00:00:00Z")

        response = client.get("/api/v1/analytics/risk-trend?limit=2")
        assert len(response.json()) == 2

    def test_limit_out_of_range_returns_422(self, client):
        response = client.get("/api/v1/analytics/risk-trend?limit=0")
        assert response.status_code == 422


class TestMitreCoverageRoute:
    def test_returns_coverage_excluding_unmapped(self, client, db_session):
        scan = _make_completed_scan(db_session)
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="root", alert_type="Root Account Used",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1", mitre_technique="T1078.001", mitre_tactic="Initial Access",
        ))
        db_session.add(FindingRecord(
            scan_run_id=scan.id, username="alice", alert_type="Unmapped Type",
            severity="Low", risk_score=10, detail="d", sla="72h",
            fingerprint="fp2",
        ))
        db_session.commit()

        response = client.get("/api/v1/analytics/mitre-coverage")
        body = response.json()
        assert len(body) == 1
        assert body[0]["mitre_technique"] == "T1078.001"

    def test_scan_id_filter_is_plumbed_through(self, client, db_session):
        scan1 = _make_completed_scan(db_session)
        scan2 = _make_completed_scan(db_session)
        db_session.add(FindingRecord(
            scan_run_id=scan1.id, username="root", alert_type="A",
            severity="Critical", risk_score=99, detail="d", sla="1h",
            fingerprint="fp1", mitre_technique="T1078.001", mitre_tactic="Initial Access",
        ))
        db_session.add(FindingRecord(
            scan_run_id=scan2.id, username="alice", alert_type="B",
            severity="High", risk_score=75, detail="d", sla="4h",
            fingerprint="fp2", mitre_technique="T1556.006", mitre_tactic="Persistence",
        ))
        db_session.commit()

        response = client.get(f"/api/v1/analytics/mitre-coverage?scan_id={scan1.id}")
        body = response.json()
        assert len(body) == 1
        assert body[0]["mitre_technique"] == "T1078.001"


class TestAlertTypeBreakdownRoute:
    def test_returns_breakdown_sorted_by_frequency(self, client, db_session):
        scan = _make_completed_scan(db_session)
        for i in range(2):
            db_session.add(FindingRecord(
                scan_run_id=scan.id, username=f"u{i}", alert_type="MFA Disabled",
                severity="High", risk_score=75, detail="d", sla="4h",
                fingerprint=f"fp{i}",
            ))
        db_session.commit()

        response = client.get("/api/v1/analytics/alert-type-breakdown")
        body = response.json()
        assert body[0]["alert_type"] == "MFA Disabled"
        assert body[0]["finding_count"] == 2
        assert body[0]["highest_severity"] == "High"


class TestScanStatsRoute:
    def test_returns_zeroed_stats_with_no_scans(self, client):
        response = client.get("/api/v1/analytics/scan-stats")
        assert response.status_code == 200
        body = response.json()
        assert body["total_scans"] == 0
        assert body["success_rate_pct"] == 0.0

    def test_reflects_real_scan_counts(self, client, db_session):
        _make_completed_scan(db_session)
        db_session.add(ScanRun(started_at=utc_now(), status="failed"))
        db_session.commit()

        response = client.get("/api/v1/analytics/scan-stats")
        body = response.json()
        assert body["total_scans"] == 2
        assert body["completed_scans"] == 1
        assert body["failed_scans"] == 1
        assert body["success_rate_pct"] == 50.0