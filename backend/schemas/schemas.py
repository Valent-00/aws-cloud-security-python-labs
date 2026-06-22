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
from pydantic import BaseModel, Field


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