"""
schemas/schemas.py
==================
Pydantic v2 schemas for all FastAPI request bodies and response models.

Why separate from models/database.py?
--------------------------------------
  SQLAlchemy models describe how data is STORED (database columns).
  Pydantic schemas describe how data is TRANSFERRED (API contract).
  Keeping them separate means:
    - You can change DB structure without breaking the API contract.
    - You can expose only the fields you want (no accidental data leaks).
    - FastAPI auto-generates accurate OpenAPI docs from these schemas.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Scan schemas
# ---------------------------------------------------------------------------

class ScanRunResponse(BaseModel):
    """
    Returned when a scan is triggered (POST /api/v1/scans)
    and when polling status (GET /api/v1/scans/{scan_id}/status).
    """
    id:             int
    started_at:     str
    completed_at:   Optional[str]   = None
    status:         str             # pending | running | completed | failed
    total_findings: int             = 0
    critical_count: int             = 0
    high_count:     int             = 0
    medium_count:   int             = 0
    low_count:      int             = 0
    info_count:     int             = 0
    error_message:  Optional[str]   = None
    ai_report:      Optional[str]   = None

    model_config = {"from_attributes": True}


class ScanHistoryItem(BaseModel):
    """
    Lightweight scan summary used in the history list
    (GET /api/v1/scans).
    """
    id:             int
    started_at:     str
    completed_at:   Optional[str]   = None
    status:         str
    total_findings: int
    critical_count: int
    high_count:     int

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Finding schemas
# ---------------------------------------------------------------------------

class FindingResponse(BaseModel):
    """Full finding detail — returned in scan results and per-user views."""
    id:           int
    scan_run_id:  int
    username:     str
    alert_type:   str
    severity:     str
    risk_score:   int
    detail:       str
    sla:          str
    fingerprint:  str
    acknowledged: bool
    ack_note:     Optional[str] = None
    ack_at:       Optional[str] = None
    acknowledged_by: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic:    Optional[str] = None

    model_config = {"from_attributes": True}


class AcknowledgeRequest(BaseModel):
    """
    Request body for acknowledging a finding
    (PATCH /api/v1/findings/{finding_id}/acknowledge).
    """
    note: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional analyst note explaining the acknowledgement.",
    )


class AcknowledgeResponse(BaseModel):
    """Returned after a finding is acknowledged."""
    id:           int
    acknowledged: bool
    ack_note:     Optional[str] = None
    ack_at:       Optional[str] = None
    acknowledged_by: Optional[str] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Dashboard summary schema
# ---------------------------------------------------------------------------

class DashboardSummary(BaseModel):
    """
    Aggregated data for the dashboard landing page
    (GET /api/v1/dashboard).

    Returns the most recent scan's severity counts plus
    the total number of unacknowledged findings across all scans.
    """
    last_scan_id:            Optional[int]  = None
    last_scan_at:            Optional[str]  = None
    last_scan_status:        Optional[str]  = None
    critical_count:          int            = 0
    high_count:              int            = 0
    medium_count:            int            = 0
    low_count:               int            = 0
    info_count:              int            = 0
    total_findings:          int            = 0
    unacknowledged_count:    int            = 0
    total_scans_run:         int            = 0


# ---------------------------------------------------------------------------
# User summary schema
# ---------------------------------------------------------------------------

class UserSummary(BaseModel):
    """
    Per-user alert summary returned by GET /api/v1/users.
    """
    username:       str
    finding_count:  int
    highest_severity: str
    acknowledged:   int
    unacknowledged: int


# ---------------------------------------------------------------------------
# S3 scan report schemas — the real boto3-data reports the Lambda writes,
# as opposed to ScanRun/FindingRecord which track main.py's own (mock-data)
# scan history in SQLite.
# ---------------------------------------------------------------------------

class S3ReportSummary(BaseModel):
    """One entry in GET /api/v1/s3-reports — lightweight, for the list view."""
    key:            str
    last_modified:  str
    size_bytes:     int


class S3ReportDetail(BaseModel):
    """
    Full report content — GET /api/v1/s3-reports/{key}.
    Mirrors the JSON shape lambda_function.py writes to S3 exactly,
    rather than reusing FindingResponse/ScanRunResponse: those are
    tied to FindingRecord/ScanRun's SQLite columns (e.g. they require
    an `id`, which an S3 report's findings don't have), so a separate
    schema avoids forcing dashboard data into a shape it doesn't have.
    """
    report_type:     str
    scan_timestamp:  str
    aws_account_id:  str
    aws_region:      Optional[str] = None
    total_findings:  int
    severity_counts: dict[str, int]
    findings:        list[dict]


class S3ReportComparison(BaseModel):
    """Returned by GET /api/v1/s3-reports/compare."""
    older_scan_timestamp:  Optional[str]   = None
    newer_scan_timestamp:  Optional[str]   = None
    new_findings:           list[dict]
    resolved_findings:      list[dict]
    severity_count_delta:   dict[str, int]


# ---------------------------------------------------------------------------
# Analytics schemas — aggregated views over main.py's own scan history
# (ScanRun/FindingRecord), for dashboard charts.
# ---------------------------------------------------------------------------

class RiskTrendPoint(BaseModel):
    """One point in GET /api/v1/analytics/risk-trend's time series."""
    scan_id:         int
    started_at:      str
    avg_risk_score:  float
    max_risk_score:  int
    total_findings:  int
    critical_count:  int
    high_count:      int
    medium_count:    int
    low_count:       int
    info_count:      int


class MitreCoverageItem(BaseModel):
    """One row in GET /api/v1/analytics/mitre-coverage."""
    mitre_tactic:     Optional[str] = None
    mitre_technique:  Optional[str] = None
    finding_count:    int


class AlertTypeBreakdownItem(BaseModel):
    """One row in GET /api/v1/analytics/alert-type-breakdown."""
    alert_type:         str
    finding_count:      int
    highest_severity:   str


class ScanStatistics(BaseModel):
    """Returned by GET /api/v1/analytics/scan-stats."""
    total_scans:             int
    completed_scans:         int
    failed_scans:            int
    in_progress_scans:       int
    success_rate_pct:        float
    avg_findings_per_scan:   float


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """
    Request body for POST /api/v1/auth/login.

    username/password are stripped of leading/trailing whitespace before
    validation. This exists specifically because shell quoting mistakes
    (e.g. a trailing space left inside quotes in a PowerShell command when
    creating an account via create_analyst.py) silently bake invisible
    whitespace into a password — the account gets created "successfully"
    with a password nobody can actually type into a login form. Stripping
    on both sides (here, and in create_analyst.py) keeps the two paths
    consistent.
    """
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username", "password")
    @classmethod
    def _strip_whitespace(cls, v: str) -> str:
        return v.strip()


class TokenResponse(BaseModel):
    """
    Returned on successful login. The frontend stores access_token and
    attaches it as `Authorization: Bearer <access_token>` on every
    subsequent request.
    """
    access_token: str
    token_type:   str = "bearer"
    username:     str
    role:         str