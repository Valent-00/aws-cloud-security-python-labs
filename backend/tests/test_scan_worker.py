"""
test_scan_worker.py
====================
Tests for main.py's _run_scan_worker() — the background thread function
that bypasses FastAPI's dependency injection by calling SessionLocal() directly.

This function is deliberately NOT tested by triggering a real POST
/api/v1/scans request: that route starts a real background thread
that calls _get_inventory_fetcher() (real or mock depending on
USE_REAL_AWS) and generate_ai_summary() (which would try to reach
a real Ollama instance). None of that belongs in a unit test. Instead,
these tests call _run_scan_worker() directly as a plain function,
with the scanner functions it depends on mocked, against the same
patched in-memory test DB used everywhere else.
"""
from unittest.mock import patch, MagicMock

import pytest

from main import _run_scan_worker, _get_inventory_fetcher
from models.database import FindingRecord, ScanRun, utc_now
from shared.scanner_engine import Finding, Severity


def _make_pending_scan(db_session) -> ScanRun:
    scan = ScanRun(started_at=utc_now(), status="pending")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


# ===========================================================================
# _get_inventory_fetcher — feature flag behaviour
# ===========================================================================

class TestGetInventoryFetcher:
    def test_returns_mock_when_use_real_aws_false(self, monkeypatch):
        monkeypatch.setattr("main.USE_REAL_AWS", False)
        fetcher = _get_inventory_fetcher()
        assert fetcher.__name__ == "fetch_cloud_inventory"

    def test_returns_real_fetcher_when_use_real_aws_true(self, monkeypatch):
        monkeypatch.setattr("main.USE_REAL_AWS", True)
        fake_real_fetcher = MagicMock(__name__="fetch_real_iam_inventory")
        with patch.dict("sys.modules", {"shared.boto3_inventory": MagicMock(
            fetch_real_iam_inventory=fake_real_fetcher
        )}):
            fetcher = _get_inventory_fetcher()
        assert fetcher.__name__ == "fetch_real_iam_inventory"

    def test_raises_when_real_fetcher_import_fails(self, monkeypatch):
        """Simulates missing boto3 / no credentials with USE_REAL_AWS=true —
        must raise rather than silently degrade to mock data, so a broken
        production configuration can never masquerade as a healthy scan."""
        monkeypatch.setattr("main.USE_REAL_AWS", True)
        # main.py imports `from cloud.boto3_inventory import ...`, and the
        # cloud/ shim re-registers itself in sys.modules under BOTH names —
        # poison both entries (None forces ImportError even when cached).
        with patch("main.USE_REAL_AWS", True), \
             patch.dict("sys.modules", {"cloud.boto3_inventory": None,
                                        "shared.boto3_inventory": None}):
            with pytest.raises(RuntimeError, match="real AWS inventory provider"):
                _get_inventory_fetcher()


# ===========================================================================
# _run_scan_worker — happy path
# ===========================================================================

class TestRunScanWorkerHappyPath:
    def test_marks_scan_completed_with_correct_severity_counts(
        self, test_engine, db_session
    ):
        scan = _make_pending_scan(db_session)

        findings = [
            Finding("root", "Root Account Used", Severity.CRITICAL, 99, "d1"),
            Finding("valent-admin", "MFA Disabled", Severity.HIGH, 75, "d2"),
        ]

        with patch("main._get_inventory_fetcher", return_value=lambda: [{"username": "root"}]), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", return_value="AI summary text"):
            _run_scan_worker(scan.id)

        db_session.expire_all()
        updated = db_session.query(ScanRun).filter(ScanRun.id == scan.id).first()
        assert updated.status == "completed"
        assert updated.critical_count == 1
        assert updated.high_count == 1
        assert updated.total_findings == 2
        assert updated.ai_report == "AI summary text"

    def test_persists_each_finding_as_a_finding_record(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)
        findings = [Finding("root", "Root Account Used", Severity.CRITICAL, 99, "detail")]

        with patch("main._get_inventory_fetcher", return_value=lambda: []), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", return_value=None):
            _run_scan_worker(scan.id)

        db_session.expire_all()
        records = db_session.query(FindingRecord).filter(
            FindingRecord.scan_run_id == scan.id
        ).all()
        assert len(records) == 1
        assert records[0].username == "root"
        assert records[0].severity == "Critical"


# ===========================================================================
# _run_scan_worker — failure paths
# ===========================================================================

class TestRunScanWorkerFailurePaths:
    def test_marks_scan_failed_on_inventory_fetch_exception(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)

        def exploding_fetcher():
            raise RuntimeError("boto3 explosion")

        with patch("main._get_inventory_fetcher", return_value=exploding_fetcher):
            _run_scan_worker(scan.id)

        db_session.expire_all()
        updated = db_session.query(ScanRun).filter(ScanRun.id == scan.id).first()
        assert updated.status == "failed"
        assert "boto3 explosion" in updated.error_message

    def test_ai_summary_failure_does_not_fail_the_whole_scan(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)
        findings = [Finding("root", "Root Account Used", Severity.CRITICAL, 99, "d")]

        with patch("main._get_inventory_fetcher", return_value=lambda: []), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", side_effect=ConnectionError("no Ollama")):
            _run_scan_worker(scan.id)

        db_session.expire_all()
        updated = db_session.query(ScanRun).filter(ScanRun.id == scan.id).first()
        assert updated.status == "completed"
        assert updated.ai_report is None
        assert updated.total_findings == 1

    def test_does_nothing_for_a_scan_id_that_does_not_exist(self, test_engine, db_session):
        _run_scan_worker(scan_id=999999)


# ===========================================================================
# _run_scan_worker — notifications
# ===========================================================================

class TestRunScanWorkerNotifications:
    def test_triggers_notification_when_critical_finding_exists(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)
        findings = [Finding("root", "Root Account Used", Severity.CRITICAL, 99, "d")]

        with patch("main._get_inventory_fetcher", return_value=lambda: []), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", return_value=None), \
             patch("main.notify_if_critical_or_high") as mock_notify:
            _run_scan_worker(scan.id)

        mock_notify.assert_called_once()
        call_kwargs = mock_notify.call_args.kwargs
        assert call_kwargs["severity_counts"]["Critical"] == 1
        assert call_kwargs["findings"][0]["username"] == "root"

    def test_a_failed_notification_does_not_fail_the_scan(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)
        findings = [Finding("root", "Root Account Used", Severity.CRITICAL, 99, "d")]

        with patch("main._get_inventory_fetcher", return_value=lambda: []), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", return_value=None), \
             patch("main.notify_if_critical_or_high", side_effect=ConnectionError("webhook down")):
            _run_scan_worker(scan.id)

        db_session.expire_all()
        updated = db_session.query(ScanRun).filter(ScanRun.id == scan.id).first()
        assert updated.status == "completed"

    def test_does_not_suppress_notifications_on_medium_only(self, test_engine, db_session):
        scan = _make_pending_scan(db_session)
        findings = [Finding("alice", "Stale Account", Severity.MEDIUM, 40, "d")]

        with patch("main._get_inventory_fetcher", return_value=lambda: []), \
             patch("main.load_baseline", return_value=[]), \
             patch("main.run_all_checks", return_value=(findings, {})), \
             patch("main.save_baseline"), \
             patch("main.generate_ai_summary", return_value=None), \
             patch("main.notify_if_critical_or_high") as mock_notify:
            _run_scan_worker(scan.id)

        mock_notify.assert_called_once()
        assert mock_notify.call_args.kwargs["severity_counts"]["Critical"] == 0
