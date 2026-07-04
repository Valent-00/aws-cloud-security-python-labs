"""
test_s3_report_routes.py
=========================
Route-level tests for the three new /api/v1/s3-reports endpoints in
main.py. boto3 is mocked the same way test_s3_reports.py mocks it —
these tests verify the ROUTE wiring (auth, REPORT_BUCKET handling,
status codes), not the S3 logic itself (already covered separately).
"""
from unittest.mock import patch

import pytest


SAMPLE_REPORT = {
    "report_type": "IAM Security Posture Scan",
    "scan_timestamp": "2026-06-26T06:31:41+00:00",
    "aws_account_id": "501421114742",
    "aws_region": "ap-southeast-2",
    "total_findings": 1,
    "severity_counts": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
    "findings": [{
        "fingerprint": "fp1", "username": "root",
        "alert_type": "Root Account Used", "severity": "Critical",
    }],
}


class TestListS3ReportsRoute:
    def test_returns_empty_list_when_report_bucket_not_configured(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "")
        response = client.get("/api/v1/s3-reports")
        assert response.status_code == 200
        assert response.json() == []

    def test_returns_reports_when_configured(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "test-bucket")
        with patch("main.list_s3_scan_reports", return_value=[
            {"key": "scan_results/2026/06/26/x.json",
             "last_modified": "2026-06-26T06:31:41+00:00", "size_bytes": 512},
        ]):
            response = client.get("/api/v1/s3-reports")
        assert response.status_code == 200
        assert response.json()[0]["key"] == "scan_results/2026/06/26/x.json"

    def test_requires_auth(self, client_real_auth):
        response = client_real_auth.get("/api/v1/s3-reports")
        assert response.status_code == 401


class TestGetS3ReportRoute:
    def test_returns_full_report_content(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "test-bucket")
        with patch("main.get_s3_scan_report", return_value=SAMPLE_REPORT):
            response = client.get(
                "/api/v1/s3-reports/scan_results/2026/06/26/x.json"
            )
        assert response.status_code == 200
        body = response.json()
        assert body["aws_account_id"] == "501421114742"
        assert body["findings"][0]["username"] == "root"

    def test_404_when_report_not_found(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "test-bucket")
        with patch("main.get_s3_scan_report", return_value=None):
            response = client.get("/api/v1/s3-reports/scan_results/missing.json")
        assert response.status_code == 404

    def test_404_when_bucket_not_configured(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "")
        response = client.get("/api/v1/s3-reports/scan_results/x.json")
        assert response.status_code == 404


class TestCompareS3ReportsRoute:
    def test_returns_comparison(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "test-bucket")
        older = dict(SAMPLE_REPORT, scan_timestamp="2026-06-25T00:00:00Z")
        newer = SAMPLE_REPORT

        def fake_get(bucket, key):
            return older if "old" in key else newer

        with patch("main.get_s3_scan_report", side_effect=fake_get), \
             patch("main.compare_scan_reports", return_value={
                 "older_scan_timestamp": "2026-06-25T00:00:00Z",
                 "newer_scan_timestamp": "2026-06-26T06:31:41+00:00",
                 "new_findings": [], "resolved_findings": [],
                 "severity_count_delta": {"Critical": 0},
             }) as mock_compare:
            # Fix M-3: keys must live under scan_results/ or the route
            # rejects them with 400 before ever touching S3.
            response = client.get(
                "/api/v1/s3-reports/compare",
                params={"older_key": "scan_results/old.json",
                        "newer_key": "scan_results/new.json"},
            )
        assert response.status_code == 200
        mock_compare.assert_called_once_with(older, newer)

    def test_404_when_older_key_missing(self, client, monkeypatch):
        monkeypatch.setattr("main.REPORT_BUCKET", "test-bucket")
        with patch("main.get_s3_scan_report", return_value=None):
            response = client.get(
                "/api/v1/s3-reports/compare",
                params={"older_key": "scan_results/missing.json",
                        "newer_key": "scan_results/new.json"},
            )
        assert response.status_code == 404