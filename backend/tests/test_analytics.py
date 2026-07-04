"""
test_analytics.py
==================
Tests for analytics.py — risk trend, MITRE coverage, alert-type
breakdown, and scan statistics. All run against the real in-memory
test DB (test_engine/db_session from conftest.py), not mocked —
these are real SQL aggregate queries, worth verifying for real.
"""
from analytics.analytics import (
    get_alert_type_breakdown,
    get_mitre_coverage,
    get_risk_trend,
    get_scan_statistics,
)
from models.database import FindingRecord, ScanRun, utc_now


def _make_completed_scan(db_session, **overrides) -> ScanRun:
    defaults = dict(
        started_at=utc_now(), completed_at=utc_now(), status="completed",
        total_findings=0, critical_count=0, high_count=0,
        medium_count=0, low_count=0, info_count=0,
    )
    defaults.update(overrides)
    scan = ScanRun(**defaults)
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


def _add_finding(db_session, scan_id, **overrides) -> FindingRecord:
    defaults = dict(
        scan_run_id=scan_id, username="root", alert_type="X",
        severity="Critical", risk_score=99, detail="d", sla="1h",
        fingerprint=f"fp-{scan_id}-{overrides.get('alert_type', 'X')}-{overrides.get('username', 'root')}",
    )
    defaults.update(overrides)
    finding = FindingRecord(**defaults)
    db_session.add(finding)
    db_session.commit()
    return finding


# ===========================================================================
# get_risk_trend
# ===========================================================================

class TestGetRiskTrend:
    def test_returns_empty_list_when_no_completed_scans(self, test_engine, db_session):
        assert get_risk_trend(db_session) == []

    def test_returns_oldest_first(self, test_engine, db_session):
        older = _make_completed_scan(db_session, started_at="2026-06-25T00:00:00Z")
        newer = _make_completed_scan(db_session, started_at="2026-06-26T00:00:00Z")

        trend = get_risk_trend(db_session)
        assert trend[0]["scan_id"] == older.id
        assert trend[1]["scan_id"] == newer.id

    def test_computes_avg_and_max_risk_score_from_findings(self, test_engine, db_session):
        scan = _make_completed_scan(db_session, total_findings=2, critical_count=1, high_count=1)
        _add_finding(db_session, scan.id, risk_score=99, alert_type="A")
        _add_finding(db_session, scan.id, risk_score=75, alert_type="B")

        trend = get_risk_trend(db_session)
        assert trend[0]["avg_risk_score"] == 87.0
        assert trend[0]["max_risk_score"] == 99

    def test_severity_counts_come_from_scan_run_not_recomputed(self, test_engine, db_session):
        """Verifies these are read directly off ScanRun's cached
        columns, not recomputed from FindingRecord — a scan with zero
        FindingRecord rows but nonzero cached counts should still
        report those cached counts correctly."""
        scan = _make_completed_scan(db_session, critical_count=5, total_findings=5)
        trend = get_risk_trend(db_session)
        assert trend[0]["critical_count"] == 5
        assert trend[0]["avg_risk_score"] == 0.0  # no FindingRecord rows to aggregate

    def test_ignores_pending_and_failed_scans(self, test_engine, db_session):
        _make_completed_scan(db_session)
        db_session.add(ScanRun(started_at=utc_now(), status="pending"))
        db_session.add(ScanRun(started_at=utc_now(), status="failed"))
        db_session.commit()

        trend = get_risk_trend(db_session)
        assert len(trend) == 1

    def test_respects_limit(self, test_engine, db_session):
        for i in range(5):
            _make_completed_scan(db_session, started_at=f"2026-06-2{i}T00:00:00Z")
        trend = get_risk_trend(db_session, limit=2)
        assert len(trend) == 2


# ===========================================================================
# get_mitre_coverage
# ===========================================================================

class TestGetMitreCoverage:
    def test_excludes_findings_with_no_mitre_mapping(self, test_engine, db_session):
        scan = _make_completed_scan(db_session)
        _add_finding(db_session, scan.id, alert_type="Mapped",
                     mitre_technique="T1078.001", mitre_tactic="Initial Access")
        _add_finding(db_session, scan.id, alert_type="Unmapped",
                     mitre_technique=None, mitre_tactic=None)

        coverage = get_mitre_coverage(db_session)
        assert len(coverage) == 1
        assert coverage[0]["mitre_technique"] == "T1078.001"

    def test_groups_and_counts_correctly(self, test_engine, db_session):
        scan = _make_completed_scan(db_session)
        for i in range(3):
            _add_finding(db_session, scan.id, alert_type=f"A{i}", username=f"u{i}",
                         mitre_technique="T1078.001", mitre_tactic="Initial Access")
        _add_finding(db_session, scan.id, alert_type="B", username="other",
                     mitre_technique="T1556.006", mitre_tactic="Persistence")

        coverage = get_mitre_coverage(db_session)
        by_technique = {c["mitre_technique"]: c["finding_count"] for c in coverage}
        assert by_technique["T1078.001"] == 3
        assert by_technique["T1556.006"] == 1
        # Sorted descending by count
        assert coverage[0]["mitre_technique"] == "T1078.001"

    def test_scopes_to_one_scan_when_scan_id_given(self, test_engine, db_session):
        scan1 = _make_completed_scan(db_session)
        scan2 = _make_completed_scan(db_session)
        _add_finding(db_session, scan1.id, alert_type="A",
                     mitre_technique="T1078.001", mitre_tactic="Initial Access")
        _add_finding(db_session, scan2.id, alert_type="B",
                     mitre_technique="T1556.006", mitre_tactic="Persistence")

        coverage = get_mitre_coverage(db_session, scan_id=scan1.id)
        assert len(coverage) == 1
        assert coverage[0]["mitre_technique"] == "T1078.001"


# ===========================================================================
# get_alert_type_breakdown
# ===========================================================================

class TestGetAlertTypeBreakdown:
    def test_counts_and_sorts_by_frequency(self, test_engine, db_session):
        scan = _make_completed_scan(db_session)
        for i in range(3):
            _add_finding(db_session, scan.id, alert_type="MFA Disabled", username=f"u{i}",
                         severity="High")
        _add_finding(db_session, scan.id, alert_type="Wildcard Permission",
                     username="root", severity="Critical")

        breakdown = get_alert_type_breakdown(db_session)
        assert breakdown[0]["alert_type"] == "MFA Disabled"
        assert breakdown[0]["finding_count"] == 3
        assert breakdown[1]["alert_type"] == "Wildcard Permission"

    def test_highest_severity_is_the_worst_seen_for_that_type(self, test_engine, db_session):
        """Regression-style check on the Python reduction logic: same
        alert_type appearing with two different severities across two
        findings should report the WORSE one, not the first or last
        encountered."""
        scan = _make_completed_scan(db_session)
        _add_finding(db_session, scan.id, alert_type="New User Created",
                     username="alice", severity="Low")
        _add_finding(db_session, scan.id, alert_type="New User Created",
                     username="root", severity="Medium")

        breakdown = get_alert_type_breakdown(db_session)
        entry = next(b for b in breakdown if b["alert_type"] == "New User Created")
        assert entry["highest_severity"] == "Medium"
        assert entry["finding_count"] == 2

    def test_scopes_to_one_scan_when_scan_id_given(self, test_engine, db_session):
        scan1 = _make_completed_scan(db_session)
        scan2 = _make_completed_scan(db_session)
        _add_finding(db_session, scan1.id, alert_type="A", severity="High")
        _add_finding(db_session, scan2.id, alert_type="B", severity="Low")

        breakdown = get_alert_type_breakdown(db_session, scan_id=scan1.id)
        assert len(breakdown) == 1
        assert breakdown[0]["alert_type"] == "A"


# ===========================================================================
# get_scan_statistics
# ===========================================================================

class TestGetScanStatistics:
    def test_zeroed_stats_with_no_scans(self, test_engine, db_session):
        stats = get_scan_statistics(db_session)
        assert stats == {
            "total_scans": 0, "completed_scans": 0, "failed_scans": 0,
            "in_progress_scans": 0, "success_rate_pct": 0.0,
            "avg_findings_per_scan": 0.0,
        }

    def test_counts_and_success_rate(self, test_engine, db_session):
        _make_completed_scan(db_session, total_findings=4)
        _make_completed_scan(db_session, total_findings=6)
        db_session.add(ScanRun(started_at=utc_now(), status="failed"))
        db_session.add(ScanRun(started_at=utc_now(), status="pending"))
        db_session.commit()

        stats = get_scan_statistics(db_session)
        assert stats["total_scans"] == 4
        assert stats["completed_scans"] == 2
        assert stats["failed_scans"] == 1
        assert stats["in_progress_scans"] == 1
        assert stats["success_rate_pct"] == 50.0
        assert stats["avg_findings_per_scan"] == 5.0