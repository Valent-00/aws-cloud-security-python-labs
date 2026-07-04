"""
main.py
=======
FastAPI application — IAM Security Scanner Backend  v2.1

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
  POST   /auth/login                         Authenticate — sets httpOnly cookie
  GET    /auth/me                            Validate cookie, return session info
  POST   /auth/logout                        Clear the auth cookie
  GET    /health                             Liveness probe

Authentication
--------------
  Every route below is protected EXCEPT /health, /api/v1/auth/login, and
  /api/v1/auth/logout. Clients authenticate via an httpOnly cookie set by
  /auth/login — there is no Authorization header involved anymore (see
  auth.py's 2026-07 security fix notes). Accounts are provisioned via
  scripts/create_analyst.py — there is no self-registration endpoint.

Design decisions
----------------
  * Scan runs are ASYNC — POST /scans returns 202 immediately with a scan ID.
    The scanner runs in a background thread. Frontend polls /status every 2s.
  * CORS is explicitly configured — required for React (port 5173) to
    call FastAPI (port 8000) without browser security errors. allow_credentials
    MUST stay True or the httpOnly auth cookie will never be sent by the browser.
  * All DB interactions use SQLAlchemy sessions via Depends(get_db).
  * No business logic lives in route handlers — routes only orchestrate.
  * API versioning: /api/v1/ prefix on every route.
  * N+1 query problem fixed in list_users — uses a single grouped query.
  * /docs, /redoc, /openapi.json are disabled entirely when ENVIRONMENT=production
    — an exposed schema hands an attacker a complete map of every endpoint,
    parameter, and response shape for free.
  * POST /auth/login is rate-limited to 5 attempts/minute per IP (slowapi) —
    without this, credential-stuffing and brute-force attacks against the
    only entry point into the system had no friction at all.

Security fixes vs v2.0 (2026-07 pre-deployment review)
--------------------------------------------------------
  * Fix #1 — JWT moved from JSON response body to an httpOnly cookie.
  * Fix #2 — /docs, /redoc, /openapi.json disabled when ENVIRONMENT=production.
  * Fix #3 — POST /auth/login rate-limited via slowapi (5/minute per IP).
  * Fix #4 — default token expiry reduced 480 → 60 minutes (see auth.py).

Bug fixes vs original
---------------------
  * Integer was missing from SQLAlchemy imports → NameError in list_users.
  * list_users had N+1 queries (one per user per count) → replaced with
    a single GROUP BY query using func.count and func.sum.
"""

import os
import sys
import logging
import threading
from contextlib import asynccontextmanager
from typing import Optional

# Load .env FIRST, before any os.getenv() calls. Using an explicit path
# relative to this file (not the current working directory) means uvicorn
# can be started from any directory and still find backend/.env correctly.
# This must happen before local imports too — api_mock_scanner.py also
# calls load_dotenv(), but that runs AFTER this module reads USE_REAL_AWS
# at module level, so relying on it as a side-effect is a race condition.
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session

# Fix #3 — rate limiting on /auth/login
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Path setup — must happen before local imports
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BACKEND_DIR)
sys.path.insert(0, os.path.join(_BACKEND_DIR, "scanner"))

from models.database import (
    AlertState,
    AnalystUser,
    FindingRecord,
    ScanRun,
    get_db,
    init_db,
    utc_now,
)
from schemas.schemas import (
    AcknowledgeRequest,
    AcknowledgeResponse,
    AlertTypeBreakdownItem,
    DashboardSummary,
    FindingResponse,
    LoginRequest,
    MitreCoverageItem,
    RiskTrendPoint,
    S3ReportComparison,
    S3ReportDetail,
    S3ReportSummary,
    ScanHistoryItem,
    ScanRunResponse,
    ScanStatistics,
    UserSummary,
)
from auth.auth import (
    clear_auth_cookie,
    create_access_token,
    get_current_user,
    set_auth_cookie,
    verify_password,
)
from analytics.analytics import (
    get_alert_type_breakdown,
    get_mitre_coverage,
    get_risk_trend,
    get_scan_statistics,
)

from cloud.s3_reports import (
    compare_scan_reports,
    get_s3_scan_report,
    is_safe_report_key,
    list_s3_scan_reports,
)



from notifications.notifications import notify_if_critical_or_high
from scanner_engine import (
    Severity,
    fetch_cloud_inventory as _mock_fetch_cloud_inventory,
    generate_ai_summary,
    load_baseline,
    run_all_checks,
    save_baseline,
)

# ---------------------------------------------------------------------------
# Runtime feature flags — set in .env or environment before starting uvicorn.
# USE_REAL_AWS=true   → fetch live IAM data via boto3 (requires configured
#                       AWS credentials — same credentials used by deploy.sh).
# USE_REAL_AWS=false  → fetch mock/hardcoded data (safe default for local
#                       dev with no AWS access and for the pytest suite).
# ---------------------------------------------------------------------------
USE_REAL_AWS: bool = os.getenv("USE_REAL_AWS", "false").lower() == "true"

# Fix #2 / #1 shared flag — also read inside auth.py to keep cookie Secure
# flag and the /docs toggle in lockstep. "production" hides docs and forces
# Secure cookies; anything else (including unset) behaves like dev.
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
_IS_PRODUCTION: bool = ENVIRONMENT == "production"


def _get_inventory_fetcher():
    """
    Return the appropriate IAM inventory fetcher based on USE_REAL_AWS.

    When USE_REAL_AWS=true, applies the same boto3 monkey-patch that
    lambda_function.py uses so both pipelines share one code path for
    real data. Falls back to the mock silently if the real fetcher
    can't be imported (missing credentials, boto3 not installed in
    this env) — logs a warning so the fallback is never invisible.

    Returns:
        Callable that returns a list of UserRecord-schema dicts.
    """
    if USE_REAL_AWS:
        try:
            from cloud.boto3_inventory import fetch_real_iam_inventory
            return fetch_real_iam_inventory
        except Exception as exc:
            # Never disguise a broken production configuration as a successful
            # scan. Returning mock findings here made the dashboard look healthy
            # while showing data from fictional users.
            raise RuntimeError(
                "USE_REAL_AWS=true, but the real AWS inventory provider could "
                "not be loaded. Install boto3 and ensure boto3_inventory.py is "
                f"available. Original error: {exc}"
            ) from exc
    return _mock_fetch_cloud_inventory


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
    # Log runtime mode at startup so it's always visible in uvicorn output.
    # If you're seeing mock data when you expect real AWS data, check this line.
    mode = "REAL AWS boto3" if USE_REAL_AWS else "MOCK data (hardcoded)"
    bucket_status = f"s3://{REPORT_BUCKET}" if REPORT_BUCKET else "not configured"
    logging.getLogger("iam_scanner.main").info(
        "Startup — scan mode: %s | report bucket: %s | environment: %s",
        mode, bucket_status, ENVIRONMENT,
    )
    if not _IS_PRODUCTION:
        logging.getLogger("iam_scanner.main").warning(
            "ENVIRONMENT=%s — /docs is ENABLED and auth cookies are NOT marked "
            "Secure. Set ENVIRONMENT=production before any real deployment.",
            ENVIRONMENT,
        )
    yield
    # Shutdown: SQLite requires no explicit cleanup


# ===========================================================================
# 2. App instance
# ===========================================================================
# Fix #2: /docs, /redoc, and the raw OpenAPI schema are only served outside
# production. In production they return 404 — nothing at that path at all,
# rather than an auth-gated page, so there's no schema to fingerprint even
# for an attacker probing for it.

app = FastAPI(
    title="IAM Security Scanner API",
    description=(
        "REST backend for the IAM Security Posture Dashboard. "
        "Triggers scans asynchronously, stores results in SQLite, "
        "and serves findings to the React frontend."
    ),
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/docs" if not _IS_PRODUCTION else None,
    redoc_url="/redoc" if not _IS_PRODUCTION else None,
    openapi_url="/openapi.json" if not _IS_PRODUCTION else None,
)


# ===========================================================================
# 3. CORS middleware
#    MUST be registered before any route definitions.
#    Allows the Vite dev server (port 5173) to call this API (port 8000).
#    allow_credentials=True is REQUIRED for the httpOnly auth cookie (Fix #1)
#    to be sent by the browser at all — without it, the cookie is silently
#    dropped on every cross-origin request regardless of withCredentials
#    being set on the frontend's Axios instance.
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
# 3b. Rate limiting — Fix #3
#     Applied specifically to POST /auth/login below. slowapi keys by
#     client IP (get_remote_address), so one abusive source can't lock out
#     other analysts sharing the API. 429 responses are handled by the
#     default slowapi handler, which returns a plain "Rate limit exceeded"
#     message — deliberately generic, matching /auth/login's own policy of
#     never giving an attacker more information than necessary.
# ===========================================================================

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


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
        # _get_inventory_fetcher() returns the real boto3 fetcher when
        # USE_REAL_AWS=true, mock otherwise. Called inside the worker
        # (not at module level) so the test suite's monkeypatching of
        # fetch_cloud_inventory still intercepts correctly.
        fetch_fn = _get_inventory_fetcher()
        iam_data = fetch_fn()

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
                mitre_technique=f.mitre_technique,
                mitre_tactic=f.mitre_tactic,
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
         # Step 8 — AI summary (best-effort, never a hard failure, but NEVER
        # silent). The old `except Exception: pass` masked every possible
        # cause — Ollama down, model not pulled, timeout, or simply no
        # findings to summarise — leaving the dashboard's AI panel blank
        # with no diagnostic trail. We now distinguish those cases in logs.
        _log = logging.getLogger("iam_scanner.main")
        ai_report: Optional[str] = None

        if not new_findings:
            # Deduplication means a re-scan of UNCHANGED IAM data yields zero
            # NEW findings — there is genuinely nothing to summarise. This is
            # the #1 reason an AI report "disappears" after the first good
            # scan. Logged explicitly so it isn't mistaken for a broken Ollama.
            _log.info(
                "Scan %s produced no new findings (all deduplicated against "
                "AlertState) — skipping AI summary. Clear AlertState + baseline "
                "to force full re-detection.", scan_id,
            )
        else:
            try:
                ai_report = generate_ai_summary(new_findings)
                if not ai_report:
                    _log.warning(
                        "generate_ai_summary returned empty for scan %s — "
                        "Ollama responded but produced no text. Check the model.",
                        scan_id,
                    )
            except Exception as exc:
                # Log the REAL error WITH traceback instead of swallowing it.
                # Still non-fatal: a scan with findings but no AI narrative
                # beats marking a successful scan as 'failed'.
                _log.exception(
                    "AI summary generation FAILED for scan %s: %s", scan_id, exc,
                )

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

        # Step 11 — Slack/Teams alert (best-effort, never a hard failure —
        # same try/except pattern as the AI summary above. A notification
        # failure is not a reason to mark a successful scan as failed).
        try:
            notify_if_critical_or_high(
                findings=[f.to_dict() for f in new_findings],
                severity_counts=severity_counts,
                scan_timestamp=scan_run.started_at,
                dashboard_url=DASHBOARD_URL or None,
            )
        except Exception:
            pass

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

# ---------------------------------------------------------------------------
# Runtime configuration — read once at startup from environment / .env file.
# See .env.example for a template with all supported variables.
# ---------------------------------------------------------------------------
REPORT_BUCKET: str = os.getenv("REPORT_BUCKET", "")
DASHBOARD_URL: str = os.getenv("DASHBOARD_URL", "")

# ── System ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"], summary="Liveness probe")
def health_check() -> dict:
    """Returns 200 if the API process is alive. Used by load balancers."""
    return {"status": "ok", "version": "2.1.0"}


# ── Auth ─────────────────────────────────────────────────────────────────────
#
# Response models defined locally rather than in schemas/schemas.py because
# that file wasn't available to edit directly — if you'd rather keep every
# response model in one place, move LoginResponse and SessionResponse into
# schemas/schemas.py and update the import above; nothing else changes.

class LoginResponse(BaseModel):
    """
    Returned by POST /auth/login. Deliberately contains NO token field —
    Fix #1 means the JWT only ever travels as an httpOnly Set-Cookie
    header, never in a JSON body a script could read.
    """
    username: str
    role: str


class SessionResponse(BaseModel):
    """Returned by GET /auth/me — mirrors LoginResponse's shape."""
    username: str
    role: str


class LogoutResponse(BaseModel):
    """Returned by POST /auth/logout."""
    message: str = "Logged out successfully."


@app.post(
    "/api/v1/auth/login",
    response_model=LoginResponse,
    tags=["Auth"],
    summary="Authenticate and receive an httpOnly session cookie",
)
@limiter.limit("5/minute")
def login(
    request: Request,   # required by slowapi's @limiter.limit — do not remove
    body: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """
    Authenticate an analyst and set the session cookie.

    Fix #1: the JWT is attached via set_auth_cookie() and never appears
    in the response body.
    Fix #3: rate-limited to 5 attempts/minute per IP — protects against
    credential stuffing and brute force against the one public entry
    point into the system.

    There is deliberately no self-registration endpoint — accounts are
    created via `python scripts/create_analyst.py`. A generic 401 is
    returned for both "unknown username" and "wrong password" so a
    caller cannot use this endpoint to enumerate valid usernames.
    """
    user = db.query(AnalystUser).filter(AnalystUser.username == body.username).first()
    if not user or not user.is_active or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token(username=user.username, role=user.role)
    set_auth_cookie(response, token)

    return LoginResponse(username=user.username, role=user.role)


@app.get(
    "/api/v1/auth/me",
    response_model=SessionResponse,
    tags=["Auth"],
    summary="Validate the session cookie and return the current analyst",
)
def get_me(current_user: AnalystUser = Depends(get_current_user)) -> SessionResponse:
    """
    Called by the frontend on every page load to hydrate session state
    without ever touching the token directly — get_current_user() has
    already validated the httpOnly cookie by the time this body runs.
    Returns 401 (via the dependency) if the cookie is missing, invalid,
    or expired, which the frontend treats as "show the login screen."
    """
    return SessionResponse(username=current_user.username, role=current_user.role)


@app.post(
    "/api/v1/auth/logout",
    response_model=LogoutResponse,
    tags=["Auth"],
    summary="Clear the session cookie",
)
def logout(response: Response) -> LogoutResponse:
    """
    Clear the auth cookie. Deliberately has no auth dependency — a client
    with an already-expired or missing cookie should still be able to
    call this and get a clean 200, rather than a confusing 401 on the
    way to logging out.

    Note: this does not revoke the JWT server-side (there is no
    revocation list — see Finding M-1 in the pre-deployment review).
    The token remains cryptographically valid until it naturally
    expires; clearing the cookie only removes it from this browser.
    """
    clear_auth_cookie(response)
    return LogoutResponse()


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
def trigger_scan(
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> ScanRun:
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
    current_user: AnalystUser = Depends(get_current_user),
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
def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> ScanRun:
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
    current_user: AnalystUser = Depends(get_current_user),
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
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> DashboardSummary:
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


# ── Analytics ────────────────────────────────────────────────────────────────
# Aggregated views over THIS dashboard's own scan history (ScanRun /
# FindingRecord) for charts — risk score trend, MITRE ATT&CK coverage,
# recurring-issue breakdown, and scan statistics. Distinct from
# /api/v1/s3-reports above: these read main.py's local (mock-data) scan
# pipeline; S3 reports hold the Lambda's real boto3-sourced findings.

@app.get(
    "/api/v1/analytics/risk-trend",
    response_model=list[RiskTrendPoint],
    tags=["Analytics"],
    summary="Risk score and severity trend across recent scans",
)
def analytics_risk_trend(
    limit: int = Query(default=30, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> list[dict]:
    """Per-scan average/max risk score plus severity counts, oldest
    first — feeds a time-series chart of security posture over time."""
    return get_risk_trend(db, limit=limit)


@app.get(
    "/api/v1/analytics/mitre-coverage",
    response_model=list[MitreCoverageItem],
    tags=["Analytics"],
    summary="Finding counts grouped by MITRE ATT&CK tactic/technique",
)
def analytics_mitre_coverage(
    scan_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> list[dict]:
    """Which MITRE ATT&CK techniques this dashboard's findings map to,
    and how often — optionally scoped to one scan via ?scan_id=."""
    return get_mitre_coverage(db, scan_id=scan_id)


@app.get(
    "/api/v1/analytics/alert-type-breakdown",
    response_model=list[AlertTypeBreakdownItem],
    tags=["Analytics"],
    summary="Finding counts grouped by alert type",
)
def analytics_alert_type_breakdown(
    scan_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> list[dict]:
    """Which kinds of issues recur most often, with each type's
    highest severity seen — optionally scoped to one scan."""
    return get_alert_type_breakdown(db, scan_id=scan_id)


@app.get(
    "/api/v1/analytics/scan-stats",
    response_model=ScanStatistics,
    tags=["Analytics"],
    summary="High-level scan run statistics",
)
def analytics_scan_stats(
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> dict:
    """Total/completed/failed scan counts, success rate, and average
    findings per completed scan."""
    return get_scan_statistics(db)


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
def list_users(
    db: Session = Depends(get_db),
    current_user: AnalystUser = Depends(get_current_user),
) -> list[UserSummary]:
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
    current_user: AnalystUser = Depends(get_current_user),
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


# ── S3 Scan Reports ──────────────────────────────────────────────────────────


@app.get(
    "/api/v1/s3-reports",
    response_model=list[S3ReportSummary],
    tags=["S3 Reports"],
    summary="List real scan reports stored in S3 by the Lambda",
)
def list_s3_reports(
    max_results: int = Query(default=50, ge=1, le=200),
    current_user: AnalystUser = Depends(get_current_user),
) -> list[dict]:
    """
    List the JSON scan reports the Lambda has uploaded to S3, newest
    first. Returns an empty list (not an error) if REPORT_BUCKET isn't
    configured or no reports exist yet — there's nothing actionable a
    caller can do differently for either case.
    """
    if not REPORT_BUCKET:
        return []
    return list_s3_scan_reports(REPORT_BUCKET, max_results=max_results)


@app.get(
    "/api/v1/s3-reports/compare",
    response_model=S3ReportComparison,
    tags=["S3 Reports"],
    summary="Compare two scan reports — what changed between them",
)
def compare_s3_reports(
    older_key: str = Query(..., description="S3 key of the earlier report"),
    newer_key: str = Query(..., description="S3 key of the later report"),
    current_user: AnalystUser = Depends(get_current_user),
) -> dict:
    """
    Diff two reports by finding fingerprint: which findings are new,
    which have resolved since, and how severity counts shifted.
    Returns 404 if either key can't be read.

    Registered BEFORE /api/v1/s3-reports/{key:path} deliberately —
    FastAPI matches routes in registration order, and that catch-all
    would otherwise swallow "/compare" as a literal key value, never
    reaching this handler at all.
    """
    if not REPORT_BUCKET:
        raise HTTPException(status_code=404, detail="REPORT_BUCKET is not configured.")

    for _label, _key in (("older_key", older_key), ("newer_key", newer_key)):
        if not is_safe_report_key(_key):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid {_label}: report keys must reference an object "
                    "under the 'scan_results/' prefix and contain no "
                    "path-traversal segments."
                ),
            )

    older = get_s3_scan_report(REPORT_BUCKET, older_key)
    if older is None:
        raise HTTPException(status_code=404, detail=f"Report '{older_key}' not found.")

    newer = get_s3_scan_report(REPORT_BUCKET, newer_key)
    if newer is None:
        raise HTTPException(status_code=404, detail=f"Report '{newer_key}' not found.")

    return compare_scan_reports(older, newer)


@app.get(
    "/api/v1/s3-reports/{key:path}",
    response_model=S3ReportDetail,
    tags=["S3 Reports"],
    summary="Fetch one real scan report's full content from S3",
)
def get_s3_report(
    key: str,
    current_user: AnalystUser = Depends(get_current_user),
) -> dict:
    """
    Fetch and return one report's full content, including every
    finding with its real MITRE mapping and risk score, exactly as
    the Lambda wrote it. `key` is a full S3 key (contains slashes,
    e.g. scan_results/2026/06/26/...json) — {key:path} is required so
    FastAPI doesn't treat the slashes as separate path segments.
    """
    if not REPORT_BUCKET:
        raise HTTPException(status_code=404, detail="REPORT_BUCKET is not configured.")

    # Fix M-3: constrain the analyst-supplied {key:path} to real report
    # objects under scan_results/ - without this, any authenticated user
    # could read arbitrary objects in REPORT_BUCKET, not just scan reports.
    if not is_safe_report_key(key):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid report key: keys must reference an object under the "
                "'scan_results/' prefix and contain no path-traversal segments."
            ),
        )

    report = get_s3_scan_report(REPORT_BUCKET, key)
    
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{key}' not found, or could not be read.",
        )
    return report


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
    current_user: AnalystUser = Depends(get_current_user),
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

    finding.acknowledged    = True
    finding.ack_note        = body.note
    finding.ack_at          = utc_now()
    finding.acknowledged_by = current_user.username
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
    current_user: AnalystUser = Depends(get_current_user),
) -> FindingRecord:
    """
    Revert a finding to unacknowledged state.
    Use this when an analyst needs to re-investigate a previously
    dismissed alert (e.g. after new evidence emerges).
    """
    finding = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    finding.acknowledged    = False
    finding.ack_note        = None
    finding.ack_at          = None
    finding.acknowledged_by = None
    db.commit()
    db.refresh(finding)
    return finding