"""
test_boto3_inventory.py
========================
Tests for boto3_inventory.py — the real-AWS IAM data fetcher used by
the Lambda scanner.

Every test here mocks boto3 itself; nothing makes a real AWS call.
That's deliberate: these tests should run in CI with zero AWS
credentials and zero cost.
"""
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from shared import boto3_inventory as bi


# ===========================================================================
# _generate_credential_report — regression test for the .read() bug
# ===========================================================================

class TestGenerateCredentialReport:
    def test_decodes_content_without_calling_read(self, sample_credential_report_csv):
        """
        Regression test for the exact bug found and fixed earlier:
        iam.get_credential_report()["Content"] is plain bytes, not a
        StreamingBody — it has no .read() method. If this regresses,
        this test fails with the same AttributeError the real Lambda
        threw in production.
        """
        fake_iam = MagicMock()
        fake_iam.get_credential_report.return_value = {
            "Content": sample_credential_report_csv
        }

        result = bi._generate_credential_report(fake_iam)

        assert "valent-admin" in result
        assert result["valent-admin"]["mfa_active"] == "false"

    def test_returns_empty_dict_on_client_error(self):
        """A denied/throttled credential-report call degrades to {},
        not a crash — callers should treat missing data as 'unknown',
        not 'no risk'."""
        fake_iam = MagicMock()
        fake_iam.generate_credential_report.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GenerateCredentialReport",
        )

        result = bi._generate_credential_report(fake_iam)
        assert result == {}

    def test_content_is_bytes_not_streaming_body(self, sample_credential_report_csv):
        """
        Explicit sanity check on the assumption the whole bug rested
        on: confirms bytes genuinely has no .read(), so if boto3 ever
        changes this API's response shape, this test is the first
        thing that explains why everything else broke.
        """
        assert isinstance(sample_credential_report_csv, bytes)
        assert not hasattr(sample_credential_report_csv, "read")


# ===========================================================================
# UserRecord schema — must match api_mock_scanner.py's mock schema
# exactly, since lambda_function.py monkey-patches one for the other.
# ===========================================================================

EXPECTED_USER_RECORD_FIELDS = {
    "username", "role", "mfa_enabled", "active_key_count", "key_age_days",
    "key_last_used_days", "password_age_days", "last_login_days",
    "account_enabled", "permissions", "last_login_hour", "known_countries",
    "last_login_country", "failed_logins_24h", "is_root",
}


class TestUserRecordSchema:
    def test_build_root_record_has_all_expected_fields(self):
        # _build_root_record takes the FULL cred_report dict, keyed by
        # username — root appears under the literal key "<root_account>".
        cred_report = {
            "<root_account>": {
                "password_last_used": "2026-06-26T06:50:58+00:00",
                "mfa_active": "true",
            }
        }
        record = bi._build_root_record(cred_report)
        assert set(record.keys()) == EXPECTED_USER_RECORD_FIELDS
        assert record["is_root"] is True
        assert record["role"] == "Root"
        assert record["mfa_enabled"] is True

    def test_root_role_is_in_privileged_roles_set(self):
        """
        api_mock_scanner.py's PRIVILEGED_ROLES = {"Administrator", "Root",
        "SuperAdmin", "Owner"}. boto3_inventory.py must keep producing
        "Root" for the root account, or every privilege-escalation
        detector silently stops firing on real data.
        """
        from shared.scoring import PRIVILEGED_ROLES
        record = bi._build_root_record({})
        assert record["role"] in PRIVILEGED_ROLES

    def test_build_user_record_role_is_in_admin_set_when_admin(self):
        """
        Same compatibility check for regular IAM users: when _is_admin()
        says yes, the resulting role string must still be one
        PRIVILEGED_ROLES recognizes.

        _get_policies() calls iam.get_paginator(name).paginate(...) for
        three operations, not direct iam.<method>() calls — mocking
        this wrong would make the test pass for the wrong reason (or
        crash on iterating a non-iterable MagicMock), so the paginator
        itself has to be mocked, not the client methods directly.
        """
        from shared.scoring import PRIVILEGED_ROLES

        def make_paginator(pages):
            paginator = MagicMock()
            paginator.paginate.return_value = pages
            return paginator

        def get_paginator_side_effect(operation_name):
            if operation_name == "list_attached_user_policies":
                return make_paginator(
                    [{"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}]
                )
            return make_paginator([])

        fake_iam = MagicMock()
        fake_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        fake_iam.get_paginator.side_effect = get_paginator_side_effect

        record = bi._build_user_record(
            fake_iam,
            user={"UserName": "valent-admin"},
            cred_report={},
        )
        assert record["role"] in PRIVILEGED_ROLES
