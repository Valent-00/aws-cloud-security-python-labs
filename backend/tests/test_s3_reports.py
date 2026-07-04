"""
test_s3_reports.py
===================
Tests for s3_reports.py — listing, fetching, and comparing scan reports
stored in S3 by lambda_function.py. All boto3 calls mocked.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import cloud.s3_reports as sr


# ===========================================================================
# list_s3_scan_reports
# ===========================================================================

class TestListS3ScanReports:
    def test_returns_only_json_keys_sorted_newest_first(self):
        fake_client = MagicMock()
        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = [{
            "Contents": [
                {"Key": "scan_results/2026/06/25/old.json",
                 "LastModified": datetime(2026, 6, 25, tzinfo=timezone.utc), "Size": 100},
                {"Key": "scan_results/2026/06/25/old_summary.txt",
                 "LastModified": datetime(2026, 6, 25, tzinfo=timezone.utc), "Size": 50},
                {"Key": "scan_results/2026/06/26/new.json",
                 "LastModified": datetime(2026, 6, 26, tzinfo=timezone.utc), "Size": 120},
            ]
        }]
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            results = sr.list_s3_scan_reports("test-bucket")

        assert len(results) == 2  # the .txt file excluded
        assert results[0]["key"] == "scan_results/2026/06/26/new.json"

    def test_respects_max_results(self):
        fake_client = MagicMock()
        fake_paginator = MagicMock()
        fake_paginator.paginate.return_value = [{
            "Contents": [
                {"Key": f"scan_results/x/{i}.json",
                 "LastModified": datetime(2026, 6, i % 28 + 1, tzinfo=timezone.utc), "Size": 10}
                for i in range(10)
            ]
        }]
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            results = sr.list_s3_scan_reports("test-bucket", max_results=3)
        assert len(results) == 3

    def test_returns_empty_list_on_client_error(self):
        from botocore.exceptions import ClientError
        fake_client = MagicMock()
        fake_paginator = MagicMock()
        fake_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListObjectsV2"
        )
        fake_client.get_paginator.return_value = fake_paginator

        with patch("boto3.client", return_value=fake_client):
            results = sr.list_s3_scan_reports("test-bucket")
        assert results == []


# ===========================================================================
# get_s3_scan_report
# ===========================================================================

class TestGetS3ScanReport:
    def test_parses_real_report_shape_correctly(self):
        report_json = (
            '{"report_type": "IAM Security Posture Scan", '
            '"scan_timestamp": "2026-06-26T06:31:41+00:00", '
            '"aws_account_id": "501421114742", "total_findings": 1, '
            '"severity_counts": {"Critical": 1}, '
            '"findings": [{"fingerprint": "fp1", "username": "root"}]}'
        )
        fake_body = MagicMock()
        fake_body.read.return_value = report_json.encode("utf-8")
        fake_client = MagicMock()
        fake_client.get_object.return_value = {"Body": fake_body}

        with patch("boto3.client", return_value=fake_client):
            result = sr.get_s3_scan_report("test-bucket", "scan_results/x.json")

        assert result["aws_account_id"] == "501421114742"
        assert result["findings"][0]["username"] == "root"

    def test_returns_none_on_missing_key(self):
        from botocore.exceptions import ClientError
        fake_client = MagicMock()
        fake_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}}, "GetObject"
        )
        with patch("boto3.client", return_value=fake_client):
            result = sr.get_s3_scan_report("test-bucket", "missing.json")
        assert result is None

    def test_returns_none_on_malformed_json(self):
        fake_body = MagicMock()
        fake_body.read.return_value = b"not valid json{{{"
        fake_client = MagicMock()
        fake_client.get_object.return_value = {"Body": fake_body}
        with patch("boto3.client", return_value=fake_client):
            result = sr.get_s3_scan_report("test-bucket", "bad.json")
        assert result is None


# ===========================================================================
# compare_scan_reports
# ===========================================================================

class TestCompareScanReports:
    def test_identifies_new_and_resolved_findings_by_fingerprint(self):
        older = {
            "scan_timestamp": "2026-06-25T00:00:00Z",
            "severity_counts": {"Critical": 1, "High": 0},
            "findings": [
                {"fingerprint": "fp1", "username": "root", "alert_type": "Wildcard Permission"},
            ],
        }
        newer = {
            "scan_timestamp": "2026-06-26T00:00:00Z",
            "severity_counts": {"Critical": 2, "High": 1},
            "findings": [
                {"fingerprint": "fp1", "username": "root", "alert_type": "Wildcard Permission"},
                {"fingerprint": "fp2", "username": "valent-admin", "alert_type": "MFA Disabled"},
            ],
        }
        result = sr.compare_scan_reports(older, newer)

        assert len(result["new_findings"]) == 1
        assert result["new_findings"][0]["username"] == "valent-admin"
        assert result["resolved_findings"] == []
        assert result["severity_count_delta"]["Critical"] == 1
        assert result["severity_count_delta"]["High"] == 1

    def test_identifies_resolved_finding_no_longer_present(self):
        older = {
            "scan_timestamp": "2026-06-25T00:00:00Z",
            "severity_counts": {"High": 1},
            "findings": [{"fingerprint": "fp1", "username": "alice"}],
        }
        newer = {
            "scan_timestamp": "2026-06-26T00:00:00Z",
            "severity_counts": {"High": 0},
            "findings": [],
        }
        result = sr.compare_scan_reports(older, newer)
        assert len(result["resolved_findings"]) == 1
        assert result["resolved_findings"][0]["username"] == "alice"
        assert result["severity_count_delta"]["High"] == -1

    def test_no_changes_gives_empty_diffs_and_zero_delta(self):
        report = {
            "scan_timestamp": "2026-06-26T00:00:00Z",
            "severity_counts": {"Critical": 2},
            "findings": [{"fingerprint": "fp1", "username": "root"}],
        }
        result = sr.compare_scan_reports(report, report)
        assert result["new_findings"] == []
        assert result["resolved_findings"] == []
        assert result["severity_count_delta"]["Critical"] == 0