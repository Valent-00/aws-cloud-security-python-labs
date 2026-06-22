"""
main.py
=======
FastAPI application — IAM Security Scanner Backend  v2.0

API Contract  (all prefixed /api/v1)
--------------------------------------
  POST   /scans                              Trigger a new scan (async)
  GET    /scans                              List scan history (paginated)
  GET    /scans/{scan_id}/status             Poll scan status + results
  GET    /scans/{scan_id}/findings           All findings for one scan
  GET    /dashboard                          Aggregated summary for landing page
  GET    /users                              Per-user finding summary
  GET    /users/{username}/findings          All findings for one user
  PATCH  /findings/{finding_id}/acknowledge  Mark a finding as reviewed
  DELETE /findings/{finding_id}/acknowledge  Un-acknowledge a finding
  GET    /health                             Liveness probe

Design decisions
----------------
  * Scan runs are ASYNC — POST /scans returns 202 immediately with a scan ID.
    The scanner runs in a background thread. Frontend polls /status every 2s.
  * CORS is explicitly configured — required for React (port 5173) to
    call FastAPI (port 8000) without browser security errors.
  * All DB interactions use SQLAlchemy sessions via Depends(get_db).
  * No business logic lives in route handlers — routes only orchestrate.
  * API versioning: /api/v1/ prefix on every route.
  * N+1 query problem fixed in list_users — uses a single grouped query.

Bug fixes vs original
---------------------
  * Integer was missing from SQLAlchemy imports → NameError in list_users.
  * list_users had N+1 queries (one per user per count) → replaced with
    a single GROUP BY query using func.count and func.sum.
"""

import os
import sys
import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Path setup — must happen before local imports
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BACKEND_DIR)
sys.path.insert(0, os.path.join(_BACKEND_DIR, "scanner"))

from models.database import (
    AlertState,
    FindingRecord,
    ScanRun,
    get_db,
    init_db,
    utc_now,
)
from schemas.schemas import (
    AcknowledgeRequest,
    AcknowledgeResponse,
    DashboardSummary,
    FindingResponse,
    ScanHistoryItem,
    ScanRunResponse,
    UserSummary,
)
from scanner.api_mock_scanner import (
    Severity,
    fetch_cloud_inventory,
    generate_ai_summary,
    load_baseline,
    run_all_checks,
    save_baseline,
)


# ===========================================================================
# 1. Lifespan — startup / shutdown hook
# ===========================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialise the SQLite database on startup.
    Creates all tables if they do not already exist.
    """
    init_db()
    yield
    # Shutdown: SQLite requires no explicit cleanup


# ===========================================================================
# 2. App instance
# ===========================================================================

app = FastAPI(
    title="IAM Security Scanner API",
    description=(
        "REST backend for the IAM Security Posture Dashboard. "
        "Triggers scans asynchronously, stores results in SQLite, "
        "and serves findings to the React frontend."
    ),
    version="2.0.0",
    lifespan=lifespan,
)


# ===========================================================================
# 3. CORS middleware
#    MUST be registered before any route definitions.
#    Allows the Vite dev server (port 5173) to call this API (port 8000).
#    Replace the origin list with your real domain in production.
# ===========================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
# 4. Background scan worker
#    Runs in a daemon thread so POST /scans returns immediately (HTTP 202).
#    The thread owns its own DB session — never shares one across threads.
# ===========================================================================

def _run_scan_worker(scan_id: int) -> None:
    """
    Execute the full IAM scanner pipeline and persist results to SQLite.

    Lifecycle of the ScanRun row:
        pending  (created by route)
        running  (set here, immediately)
        completed | failed  (set here, on finish)

    Steps
    -----
    1.  Mark scan as 'running'.
    2.  Fetch live IAM inventory from fetch_cloud_inventory().
    3.  Load baseline (or empty list on first run).
    4.  Load active alert fingerprints from AlertState table.
    5.  Run all detectors + field-level drift + deduplication.
    6.  Persist each new Finding as a FindingRecord row.
    7.  Sync updated fingerprints into AlertState (insert only new ones).
    8.  Attempt AI summary via Ollama — skipped gracefully if unavailable.
    9.  Update baseline file to current snapshot.
    10. Mark scan as 'completed' with severity counts.

    On any unhandled exception: mark scan as 'failed' with error message.
    """
    from models.database import SessionLocal

    db: Session = SessionLocal()

    try:
        # Step 1 — mark running
        scan_run: ScanRun = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not scan_run:
            return
        scan_run.status = "running"
        db.commit()

        # Step 2 — fetch inventory
        iam_data = fetch_cloud_inventory()

        # Step 3 — load baseline
        baseline = load_baseline() or []

        # Step 4 — load alert dedup state from DB
        alert_state: dict[str, str] = {
            row.fingerprint: row.first_seen
            for row in db.query(AlertState)
                          .filter(AlertState.resolved == False)  # noqa: E712
                          .all()
        }

        # Step 5 — run all checks
        new_findings, updated_state = run_all_checks(iam_data, baseline, alert_state)

        # Step 6 — persist findings
        severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in new_findings:
            severity_counts[f.severity.value] += 1
            db.add(FindingRecord(
                scan_run_id=scan_id,
                username=f.username,
                alert_type=f.alert_type,
                severity=f.severity.value,
                risk_score=f.risk_score,
                detail=f.detail,
                sla=f.sla,
                fingerprint=f.fingerprint,
            ))

        # Step 7 — sync alert state (insert new fingerprints only)
        existing_fps: set[str] = {
            row.fingerprint
            for row in db.query(AlertState.fingerprint).all()
        }
        for fp, first_seen in updated_state.items():
            if fp not in existing_fps:
                db.add(AlertState(fingerprint=fp, first_seen=first_seen))

        # Step 8 — AI summary (best-effort, never a hard failure)
        ai_report: Optional[str] = None
        try:
            ai_report = generate_ai_summary(new_findings)
        except Exception:
            pass

        # Step 9 — update baseline
        save_baseline(iam_data)

        # Step 10 — commit findings first, then re-fetch scan_run and update it.
        # We re-query scan_run here because SQLAlchemy may have expired the object
        # during the file I/O in save_baseline(), causing a silent reset on commit.
        db.commit()  # commit findings + alert state first

        scan_run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        scan_run.completed_at   = utc_now()
        scan_run.status         = "completed"
        scan_run.total_findings = len(new_findings)
        scan_run.critical_count = severity_counts.get("Critical", 0)
        scan_run.high_count     = severity_counts.get("High",     0)
        scan_run.medium_count   = severity_counts.get("Medium",   0)
        scan_run.low_count      = severity_counts.get("Low",      0)
        scan_run.info_count     = severity_counts.get("Info",     0)
        scan_run.ai_report      = ai_report
        db.commit()

    except Exception as exc:
        db.rollback()
        try:
            scan_run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
            if scan_run:
                scan_run.status        = "failed"
                scan_run.completed_at  = utc_now()
                scan_run.error_message = str(exc)
                db.commit()
        except Exception:
            pass  # DB itself may be broken — nothing more we can do
    finally:
        db.close()


# ===========================================================================
# 5. Routes
# ===========================================================================

# ── System ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"], summary="Liveness probe")
def health_check() -> dict:
    """Returns 200 if the API process is alive. Used by load balancers."""
    return {"status": "ok", "version": "2.0.0"}


# ── Scans ───────────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/scans",
    response_model=ScanRunResponse,
    status_code=202,
    tags=["Scans"],
    summary="Trigger a new scan",
    description=(
        "Starts a background IAM scan and returns HTTP 202 immediately. "
        "Poll GET /api/v1/scans/{scan_id}/status every 2 seconds "
        "until status is 'completed' or 'failed'."
    ),
)
def trigger_scan(db: Session = Depends(get_db)) -> ScanRun:
    """
    Create a ScanRun record (status=pending), launch the background worker
    thread, and return the scan record immediately so the client can poll.
    """
    scan_run = ScanRun(started_at=utc_now(), status="pending")
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(scan_run.id,),
        daemon=True,   # thread exits when the main process exits
    )
    thread.start()

    return scan_run


@app.get(
    "/api/v1/scans",
    response_model=list[ScanHistoryItem],
    tags=["Scans"],
    summary="List scan history",
)
def list_scans(
    limit:  int = Query(default=20, ge=1, le=100, description="Max rows to return"),
    offset: int = Query(default=0,  ge=0,         description="Pagination offset"),
    db: Session = Depends(get_db),
) -> list[ScanRun]:
    """
    Return recent scan runs in reverse chronological order (newest first).
    Supports pagination via limit / offset query parameters.
    """
    return (
        db.query(ScanRun)
          .order_by(ScanRun.id.desc())
          .offset(offset)
          .limit(limit)
          .all()
    )


@app.get(
    "/api/v1/scans/{scan_id}/status",
    response_model=ScanRunResponse,
    tags=["Scans"],
    summary="Poll scan status",
)
def get_scan_status(scan_id: int, db: Session = Depends(get_db)) -> ScanRun:
    """
    Return the current status and result counts for one scan run.
    Frontend polls this every 2 seconds until status = 'completed' | 'failed'.
    """
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan_run:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return scan_run


@app.get(
    "/api/v1/scans/{scan_id}/findings",
    response_model=list[FindingResponse],
    tags=["Scans"],
    summary="Get findings for a scan",
)
def get_scan_findings(
    scan_id:  int,
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: Critical | High | Medium | Low | Info",
    ),
    db: Session = Depends(get_db),
) -> list[FindingRecord]:
    """
    Return all findings produced by a specific scan run, sorted by
    risk_score descending. Optionally filter by a severity band.
    Returns 404 if the scan ID does not exist.
    """
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan_run:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    query = (
        db.query(FindingRecord)
          .filter(FindingRecord.scan_run_id == scan_id)
          .order_by(FindingRecord.risk_score.desc())
    )
    if severity:
        query = query.filter(FindingRecord.severity == severity)

    return query.all()


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.get(
    "/api/v1/dashboard",
    response_model=DashboardSummary,
    tags=["Dashboard"],
    summary="Aggregated summary for landing page",
)
def get_dashboard(db: Session = Depends(get_db)) -> DashboardSummary:
    """
    Return severity counts from the most recent completed scan,
    plus the total unacknowledged finding count across all scans.

    Returns zeroed counts if no completed scan exists yet.
    """
    last_scan: Optional[ScanRun] = (
        db.query(ScanRun)
          .filter(ScanRun.status == "completed")
          .order_by(ScanRun.id.desc())
          .first()
    )

    total_scans: int = db.query(ScanRun).count()

    unacknowledged: int = (
        db.query(FindingRecord)
          .filter(FindingRecord.acknowledged == False)  # noqa: E712
          .count()
    )

    if not last_scan:
        return DashboardSummary(
            total_scans_run=total_scans,
            unacknowledged_count=unacknowledged,
        )

    return DashboardSummary(
        last_scan_id=last_scan.id,
        last_scan_at=last_scan.completed_at,
        last_scan_status=last_scan.status,
        critical_count=last_scan.critical_count,
        high_count=last_scan.high_count,
        medium_count=last_scan.medium_count,
        low_count=last_scan.low_count,
        info_count=last_scan.info_count,
        total_findings=last_scan.total_findings,
        unacknowledged_count=unacknowledged,
        total_scans_run=total_scans,
    )


# ── Users ────────────────────────────────────────────────────────────────────

# Severity order used for sorting — Critical is most urgent (0)
_SEV_ORDER: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
}


@app.get(
    "/api/v1/users",
    response_model=list[UserSummary],
    tags=["Users"],
    summary="Per-user finding summary",
)
def list_users(db: Session = Depends(get_db)) -> list[UserSummary]:
    """
    Return a finding summary grouped by username, sorted by highest severity.

    Uses a single SQL GROUP BY query to count acknowledged and total findings
    per user — avoids the N+1 query problem of querying per-user in a loop.
    """
    # Single query: for each username, count total and acknowledged findings
    rows = (
        db.query(
            FindingRecord.username,
            func.count(FindingRecord.id).label("total"),
            func.sum(
                func.cast(FindingRecord.acknowledged == True, Integer)  # noqa: E712
            ).label("acked_count"),
        )
        .group_by(FindingRecord.username)
        .all()
    )

    if not rows:
        return []

    # Get the highest (most severe) severity per user in one query
    # Using a subquery to find min severity rank per user
    sev_rows = (
        db.query(FindingRecord.username, FindingRecord.severity)
          .all()
    )

    # Build a map: username → worst severity string
    user_worst: dict[str, str] = {}
    for uname, sev in sev_rows:
        current_rank = _SEV_ORDER.get(user_worst.get(uname, "Info"), 4)
        new_rank     = _SEV_ORDER.get(sev, 4)
        if new_rank < current_rank:
            user_worst[uname] = sev

    result: list[UserSummary] = []
    for row in rows:
        acked       = int(row.acked_count or 0)
        total       = int(row.total or 0)
        worst_sev   = user_worst.get(row.username, "Info")

        result.append(UserSummary(
            username=row.username,
            finding_count=total,
            highest_severity=worst_sev,
            acknowledged=acked,
            unacknowledged=total - acked,
        ))

    # Sort by severity — Critical users appear first
    return sorted(result, key=lambda u: _SEV_ORDER.get(u.highest_severity, 4))


@app.get(
    "/api/v1/users/{username}/findings",
    response_model=list[FindingResponse],
    tags=["Users"],
    summary="All findings for one user",
)
def get_user_findings(
    username: str,
    db: Session = Depends(get_db),
) -> list[FindingRecord]:
    """
    Return all findings across all scan runs for a specific username,
    sorted by risk_score descending.
    Returns 404 if the username has no findings on record.
    """
    findings = (
        db.query(FindingRecord)
          .filter(FindingRecord.username == username)
          .order_by(FindingRecord.risk_score.desc())
          .all()
    )
    if not findings:
        raise HTTPException(
            status_code=404,
            detail=f"No findings found for user '{username}'.",
        )
    return findings


# ── Findings — acknowledge / un-acknowledge ──────────────────────────────────

@app.patch(
    "/api/v1/findings/{finding_id}/acknowledge",
    response_model=AcknowledgeResponse,
    tags=["Findings"],
    summary="Acknowledge a finding",
)
def acknowledge_finding(
    finding_id: int,
    body: AcknowledgeRequest,
    db: Session = Depends(get_db),
) -> FindingRecord:
    """
    Mark a finding as reviewed by a SOC analyst.
    An optional note can be attached to document the analyst's decision.
    Acknowledged findings remain visible but are visually de-emphasised
    in the dashboard to reduce alert fatigue.
    """
    finding = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    finding.acknowledged = True
    finding.ack_note     = body.note
    finding.ack_at       = utc_now()
    db.commit()
    db.refresh(finding)
    return finding


@app.delete(
    "/api/v1/findings/{finding_id}/acknowledge",
    response_model=AcknowledgeResponse,
    tags=["Findings"],
    summary="Remove acknowledgement from a finding",
)
def unacknowledge_finding(
    finding_id: int,
    db: Session = Depends(get_db),
) -> FindingRecord:
    """
    Revert a finding to unacknowledged state.
    Use this when an analyst needs to re-investigate a previously
    dismissed alert (e.g. after new evidence emerges).
    """
    finding = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    finding.acknowledged = False
    finding.ack_note     = None
    finding.ack_at       = None
    db.commit()
    db.refresh(finding)
    return finding