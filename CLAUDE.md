# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

IAM Security Scanner v2.1 — a full-stack Cloud Security Posture Management (CSPM) portfolio project.
It monitors cloud IAM users for credential hygiene, privilege risk, behavioural anomalies, and config
drift, surfacing findings in a React dashboard with an analyst acknowledge/review workflow.
`README.md` has the detector catalogue, feature list, and env var reference, but predates this
repo's `shared/` refactor and its 2026-07 security hardening — see "Docs vs. current code" below
before trusting its API list, project-structure diagram, or auth description. `SECURITY.md` is
current and should be read before touching auth, cookies, S3 report handling, or webhook senders.

Two runtimes share one engine:

1. **`backend/` + `frontend/`** — local dev dashboard (FastAPI + React), on-demand "Run Scan Now",
   backed by SQLite.
2. **`lambda-deployment/`** — standalone AWS Lambda packaging, triggered daily by EventBridge,
   writing real boto3-sourced results to S3. `deploy.sh` provisions the S3 bucket, IAM execution
   role, Lambda function, and EventBridge rule.

The FastAPI backend's `/api/v1/s3-reports*` routes read the Lambda's real S3 output; every other
route reads the backend's own SQLite tables from its own (usually mock-data) scan runs. Check which
pipeline produced the data before tracing a bug across the two.

## Commands

### Backend (FastAPI)

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows; source venv/bin/activate on macOS/Linux
pip install -r requirements.txt
cp .env.example .env           # set JWT_SECRET_KEY, USE_REAL_AWS, REPORT_BUCKET, ENVIRONMENT

uvicorn main:app --reload --port 8000
```

`/docs`, `/redoc`, `/openapi.json` are only served when `ENVIRONMENT` is unset or `development`; they
are disabled entirely when `ENVIRONMENT=production` (see SECURITY.md Fix #2). `ENVIRONMENT` also
controls whether the auth cookie gets the `Secure` flag — always set it to `production` before any
real deployment.

Every route except `/health`, `/api/v1/auth/login`, and `/api/v1/auth/logout` requires the httpOnly
session cookie set by login. There is no self-registration endpoint — provision an analyst account
first:

```bash
cd backend
python scripts/create_analyst.py
```

Other one-off scripts in `backend/scripts/`: `clear_alert_state.py` (destructive — resets dedup
state so every finding re-alerts as new; demo/dev only) and `backfill_mitre_mapping.py` (populates
MITRE fields on findings written before that feature existed).

### Frontend (React + Vite)

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=" > .env
npm run dev        # http://localhost:5173, proxies /api to :8000 (see vite.config.js)
npm run build
npm run preview
```

No lint/test scripts are configured in `frontend/package.json`. Only variables prefixed `VITE_` may
ever go in `frontend/.env` — Vite bakes them into the public bundle at build time (see SECURITY.md
L-2). `VITE_API_BASE_URL` is the only one in use.

### Tests (backend only)

```bash
cd backend
pytest                          # whole suite
pytest tests/test_auth.py       # one file
pytest tests/test_auth.py::test_login_rejects_wrong_password   # one test
```

No `pytest.ini`/`pyproject.toml` — pytest runs with defaults. `tests/conftest.py` monkeypatches
`models.database.engine`/`SessionLocal` to a `StaticPool` in-memory SQLite DB before anything else
touches them, so tests never hit `backend/data/iam_scanner.db`. Two TestClient fixtures exist:
`client` (both `get_db` and `get_current_user` overridden — for route-logic tests that don't care
about auth) and `client_real_auth` (only `get_db` overridden — for testing the real login flow and
that protected routes actually reject bad/missing auth). The `_reset_login_rate_limiter` autouse
fixture resets slowapi's counter every test, since without it the sixth login test within a minute
would spuriously 429 (rate limit state persists across tests otherwise).

### Optional: AI reports (Ollama)

`generate_ai_summary()` / incident-explanation features call a local Ollama server. Not required for
core scanning; failures are swallowed (best-effort) and never fail a scan. See README for setup
(`ollama pull llama3.2`, `ollama serve`, config via `OLLAMA_*` env vars).

### Lambda deployment

`lambda-deployment/deploy.sh` packages `lambda_function.py` + `scanner/` + `shared/` into a zip
(boto3 excluded — provided by the Lambda runtime), creates/updates the S3 bucket, IAM execution role,
Lambda function, and a daily EventBridge trigger. Edit the CONFIGURATION block at the top before
running it, and treat running it as a real-AWS side-effecting operation, not a routine dev command.

## Architecture

### `shared/` is the real scanner engine — everything else is a compatibility shim

All detection logic, scoring, boto3 inventory fetching, and notification-sending now live in
`shared/scanner_engine.py` (~1600 lines), with `shared/detectors.py` and `shared/scoring.py` as
thin re-export façades over it, and `shared/boto3_inventory.py` / `shared/notifications.py`
alongside. This eliminated an earlier design where the scanner file was duplicated verbatim between
`backend/` and `lambda-deployment/`.

`backend/scanner/api_mock_scanner.py`, `backend/scanner/scanner_engine.py`,
`backend/cloud/boto3_inventory.py`, and `backend/notifications/notifications.py` are all **one-line
compatibility shims** using the same trick — e.g.:

```python
import sys
from shared import scanner_engine as _implementation
sys.modules[__name__] = _implementation
```

They exist purely so old import paths (`from scanner.api_mock_scanner import ...`) keep working.
`lambda_function.py` imports `shared.scanner_engine`/`shared.boto3_inventory`/`shared.notifications`
directly. **When changing detection/scoring/notification logic, edit the `shared/` module — editing
a `backend/` shim does nothing.**

Scan flow, orchestrated by `run_all_checks()` in `shared/scanner_engine.py`:

1. `fetch_cloud_inventory()` returns hardcoded mock `UserRecord`s by default. `USE_REAL_AWS=true`
   swaps it for `shared.boto3_inventory.fetch_real_iam_inventory` (falls back to mock with a logged
   warning if that import fails — missing creds/boto3). The Lambda entry point does the same swap by
   monkey-patching `scanner.fetch_cloud_inventory` directly.
2. 13 `check_*` detectors each return `Finding`s (MFA disabled, stale/never-used/multiple keys,
   password rotation, dormant admin, stale account, disabled-account-with-key, wildcard permission,
   root usage, brute force, off-hours login, geo anomaly).
3. `detect_field_level_drift()` diffs against the previous run's baseline (MFA flips, role escalation,
   new users, key-age jumps).
4. `deduplicate_findings()` fingerprints findings (SHA-256) against persisted `AlertState` so repeat
   alerts don't re-fire every scan.
5. Each `Finding` carries a MITRE ATT&CK technique/tactic and a computed `risk_score` → `Severity`
   band (Critical/High/Medium/Low/Info).
6. `generate_ai_summary()` / `generate_incident_explanation()` optionally call Ollama — best-effort,
   never blocks or fails the scan.

### Backend package layout (`backend/`)

Reorganized into subpackages, each backed by `shared/` where noted:
- `auth/auth.py` — JWT creation/verification, bcrypt password hashing, `get_current_user`,
  `require_role()`. Real implementation lives here (not a shim).
- `analytics/analytics.py` — aggregate views (risk trend, MITRE coverage, alert-type breakdown, scan
  stats) over this backend's own SQLite `ScanRun`/`FindingRecord` tables. Real implementation.
- `cloud/` — `boto3_inventory.py` (shim → `shared`), `cloudtrail_inventory.py` (real), `s3_reports.py`
  (real; reads the Lambda's S3-stored reports directly, no DB involved — validates S3 keys against
  path traversal per SECURITY.md Fix M-3).
- `notifications/notifications.py` — shim → `shared.notifications`.
- `scanner/` — both files are shims → `shared.scanner_engine`.
- `models/database.py` — SQLAlchemy models, SQLite-backed: `ScanRun` (`scan_runs`), `FindingRecord`
  (`findings`), `AlertState` (`alert_state`), `AnalystUser` (`analyst_users`). `init_db()` creates
  tables on startup if missing; no migration tool (SQLite/dev-only).

### `backend/main.py` — read the module docstring first

It documents the full API contract, auth model, design decisions, and the 2026-07 security-fix list
inline, and is more current than the README. Key points:

- **Auth is httpOnly-cookie based, not a bearer token in the response body.** `POST /auth/login` sets
  the cookie; `GET /auth/me` validates it; `POST /auth/logout` clears it. `allow_credentials=True` on
  CORS must stay on or the cookie never reaches the API from the browser. There is no server-side
  token revocation — logout only clears the cookie client-side, the JWT itself stays valid until
  `ACCESS_TOKEN_EXPIRE_MINUTES` (default 60) elapses; see SECURITY.md's M-1 for why that's accepted.
- `POST /api/v1/scans` returns 202 immediately; the scan runs in a **daemon background thread**
  (`_run_scan_worker`) with its own DB session (SQLAlchemy sessions are never shared across threads).
  Frontend polls `GET /scans/{id}/status` every 2s.
- `POST /auth/login` is rate-limited to 5/minute per IP via slowapi (`limiter` on `app.state`) —
  tests must reset this between runs (see conftest note above).
- No business logic in route handlers — routes only orchestrate `shared`/subpackage functions.
- Route registration order matters: `/api/v1/s3-reports/compare` is registered before the
  `/api/v1/s3-reports/{key:path}` catch-all, otherwise the catch-all swallows "compare" as a literal
  S3 key.

### Frontend (`frontend/src/`)

React 18 + Vite + Tailwind (`darkMode: 'class'`) + React Router + Recharts. `api/client.js` holds the
single Axios instance. `pages/` (Dashboard, Findings, UserDetail, ScanHistory, Analytics, AwsReports,
Login) map roughly 1:1 to backend route groups. `components/ui.jsx` holds shared presentational
primitives (cards, empty states, disclosure, error banners) so layout/spacing/dark-mode stay
consistent across pages — no data fetching or business logic there. `theme.jsx` owns light/dark theme
state (persisted to localStorage). `constants/security.js` is frontend-only reference data (severity
colors/icons, MITRE technique display names, per-alert-type remediation text) — presentational only,
mirrors but does not replace backend logic.

## Docs vs. current code

`README.md` was brought up to date to match this repo's current state (`shared/` engine, cookie-based
auth, rate limiting, analytics/AWS-reports/AwsReports additions) — treat it as accurate going forward,
but re-check it against the source whenever main.py's docstring, `shared/`, or the auth flow change,
since it's a plain markdown file that won't update itself. `SECURITY.md` is accurate and current —
read it before changing anything auth-, cookie-, S3-report-, or webhook-related, and note its logged
incident: `backend/.env` was once committed and pushed (leaked JWT secret since rotated; `.gitignore`
was silently inert due to a UTF-16 encoding bug, now fixed and rewritten in UTF-8). Never commit
`.env` files — copy `backend/.env.example`.
