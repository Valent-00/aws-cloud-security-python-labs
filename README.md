# IAM Security Scanner

A full-stack **Cloud IAM Security Posture Management (CSPM)** platform: it inventories IAM user accounts (mock data or a live AWS account), runs 13+ security detectors against them, maps findings to MITRE ATT&CK, and surfaces everything in an authenticated React dashboard with AI-generated executive reports and real-time Slack / Microsoft Teams alerting.

Built as a Bachelor's-level cybersecurity final-year project. Detection logic is modelled on real-world CSPM frameworks including AWS Security Hub, Microsoft Defender for Cloud, and the CIS Benchmarks for IAM.

---

## Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Creating an Analyst Account](#creating-an-analyst-account)
- [Scanning a Real AWS Account](#scanning-a-real-aws-account)
- [Optional Integrations](#optional-integrations)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [AWS Lambda Deployment](#aws-lambda-deployment)
- [Security](#security)

---

## Key Features

### Detection engine

Thirteen detectors plus field-level drift detection, each producing severity-banded, MITRE-mapped findings:

| Check | Severity | Description |
|---|---|---|
| MFA Disabled | Medium–High | Account has no multi-factor authentication |
| Stale Key | Low–Critical | API key older than the rotation policy limit |
| Never-Used Key | Low | Key created but never called — orphaned attack surface |
| Multiple Active Keys | Low–Medium | User holds more than the allowed number of keys |
| No Password Rotation | Medium–Critical | Password exceeds maximum age policy |
| Dormant Admin | High | Privileged account with no login in N days |
| Stale Account | Low–Medium | Any account inactive beyond threshold |
| Disabled Account With Key | Medium–High | Disabled account still holds an active API key |
| Wildcard Permission | High | IAM policy contains `*:*` — violates least privilege |
| Root Account Used | Critical | Cloud root account logged in recently |
| Brute Force Indicator | Medium–High | Failed logins exceed threshold in 24 h |
| Off-Hours Login | Low | Login outside configured business hours |
| Geo Anomaly | High | Login from a country outside the user's baseline |
| Field-Level Drift | varies | MFA flips, role escalations, key-age jumps between scans |

### Platform

- **Authenticated analyst workflow** — JWT login (httpOnly cookie, bcrypt-hashed passwords, rate-limited), acknowledge/revert findings with notes. No self-registration; accounts are provisioned out-of-band.
- **Real AWS mode** — swap the mock inventory for live `boto3` IAM + CloudTrail data with a single environment flag.
- **Alert deduplication** — SHA-256 fingerprinting so only *new* state changes fire alerts across runs.
- **MITRE ATT&CK analytics** — risk trend, technique coverage, and alert-type breakdown charts.
- **AI executive reports** — optional local LLM (Ollama) turns raw findings into professional incident summaries.
- **Real-time notifications** — Critical/High findings pushed to Slack and Microsoft Teams (Workflows webhooks).
- **S3 report archive** — browse and diff historical scan reports stored in S3 by the Lambda scanner.
- **Scheduled cloud scanning** — AWS Lambda + EventBridge deployment runs the same engine daily, unattended.
- **Structured JSON export** — machine-readable findings for SIEM ingestion.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                       React Frontend  (port 5173)             │
│  Login │ Dashboard │ Findings │ Users │ Analytics │           │
│  Scan History │ AWS Reports                                   │
└───────────────────────────┬───────────────────────────────────┘
                            │ HTTPS (Axios, httpOnly JWT cookie)
                            ▼
┌───────────────────────────────────────────────────────────────┐
│                  FastAPI Backend  (port 8000)                 │
│  auth (JWT/bcrypt/rate-limit) │ scans │ dashboard │           │
│  analytics (MITRE) │ users │ findings │ s3-reports            │
└───────┬──────────────────┬──────────────────┬─────────────────┘
        │ SQLAlchemy       │ boto3 (optional) │ HTTP (optional)
        ▼                  ▼                  ▼
  ┌──────────┐   ┌──────────────────┐   ┌─────────────┐
  │  SQLite  │   │ AWS IAM /        │   │ Ollama LLM  │
  │ database │   │ CloudTrail / S3  │   │ (port 11434)│
  └──────────┘   └──────────────────┘   └─────────────┘
        ▲
        │ shared engine (shared/)
┌───────┴───────────────────────────────────────────────────────┐
│  Scanner Engine — 13 detectors, drift detection, dedup,       │
│  risk scoring, MITRE mapping, Slack/Teams notifications       │
│  (also packaged into an AWS Lambda for daily scheduled scans) │
└───────────────────────────────────────────────────────────────┘
```

The detection engine lives in `shared/` and is consumed by **both** the FastAPI backend (on-demand scans from the dashboard) and the AWS Lambda (daily scheduled scans) — one codebase, two runtimes.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn, SQLAlchemy 2, Pydantic 2, SQLite |
| Auth | PyJWT (httpOnly cookie), bcrypt, slowapi (rate limiting) |
| Cloud | boto3 (IAM, CloudTrail, S3), AWS Lambda + EventBridge |
| Frontend | React 18, Vite 5, Tailwind CSS 3, React Router 6, Axios, Recharts |
| AI (optional) | Ollama running `llama3.2` locally |
| Alerting (optional) | Slack Incoming Webhooks, Microsoft Teams Workflows webhooks |

---

## Project Structure

```
IAM-Scanner2/
├── backend/
│   ├── main.py                 # FastAPI app — all routes
│   ├── requirements.txt
│   ├── .env.example            # Copy to .env and configure
│   ├── auth/                   # JWT + bcrypt authentication
│   ├── cloud/                  # boto3 IAM inventory, CloudTrail, S3 reports
│   ├── analytics/              # MITRE coverage, risk trend aggregation
│   ├── notifications/          # Slack / Teams alert senders
│   ├── models/                 # SQLAlchemy models + DB init
│   ├── schemas/                # Pydantic request/response schemas
│   ├── scanner/                # Scan orchestration (engine lives in shared/)
│   ├── scripts/
│   │   ├── create_analyst.py   # Provision analyst login accounts
│   │   ├── clear_alert_state.py
│   │   └── backfill_mitre_mapping.py
│   └── tests/                  # pytest suite (12 modules)
│
├── shared/                     # Detection engine shared by backend + Lambda
│   ├── scanner_engine.py       # 13 detectors, drift, dedup, orchestration
│   ├── detectors.py            # Public detector API
│   ├── scoring.py              # Risk scoring
│   ├── boto3_inventory.py      # Real AWS inventory fetcher
│   └── notifications.py        # Webhook alerting
│
├── frontend/
│   ├── vite.config.js          # Dev proxy → backend port 8000
│   └── src/
│       ├── api/client.js       # Axios instance + all API calls
│       ├── components/         # SeverityBadge, FindingCard, ScanTrigger, AiReportPanel
│       └── pages/              # Login, Dashboard, Findings, UserDetail,
│                               # Analytics, ScanHistory, AwsReports
│
├── lambda-deployment/
│   ├── lambda_function.py      # Lambda entry point (daily EventBridge scans → S3)
│   ├── deploy.sh
│   └── iam_execution_role.json # Least-privilege execution role
│
├── SECURITY.md                 # Security posture: controls, accepted risks
└── README.md
```

---

## Getting Started

### Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Python | 3.10+ | `python --version` |
| Node.js | 18+ | `node --version` |
| npm | 8+ | `npm --version` |
| Ollama *(optional — AI reports)* | any | `ollama --version` |
| AWS credentials *(optional — real scans)* | — | `aws sts get-caller-identity` |

### 1. Backend

```bash
cd backend

python -m venv venv
venv\Scripts\activate            # Windows
# source venv/bin/activate       # macOS / Linux

pip install -r requirements.txt

# Configure environment — NEVER commit the resulting .env
cp .env.example .env
```

Edit `backend/.env` and set at minimum a strong `JWT_SECRET_KEY` (e.g. `python -c "import secrets; print(secrets.token_urlsafe(64))"`).

### 2. Frontend

```bash
cd frontend
npm install
cp .env.example .env             # defaults use the Vite dev proxy — no edits needed
```

### 3. Run (two terminals)

```bash
# Terminal 1 — backend
cd backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm run dev
```

Open **http://localhost:5173**, log in with the analyst account you create below, and click **Run Scan Now**.

---

## Creating an Analyst Account

There is deliberately **no sign-up endpoint** — a security scanner that lets anyone self-enrol would undermine the access control it demonstrates. Accounts are provisioned out-of-band by whoever has shell access:

```bash
cd backend
python scripts/create_analyst.py <username>            # analyst role
python scripts/create_analyst.py <username> --role admin
```

The password is prompted interactively (hidden input, confirmed twice).

---

## Scanning a Real AWS Account

By default the scanner runs against a built-in mock inventory, so the full pipeline works with zero cloud setup. To scan a live AWS account:

1. Provide AWS credentials the standard way (`aws configure`, environment variables, or an instance/task role). The scanner needs read-only IAM and CloudTrail access.
2. In `backend/.env` set:

   ```ini
   USE_REAL_AWS=true
   AWS_DEFAULT_REGION=<your-region>
   REPORT_BUCKET=<your-reports-bucket>   # only needed for the S3 reports page
   ```

3. Restart the backend and run a scan. `shared/boto3_inventory.py` fetches real users, keys, MFA state, and CloudTrail login events, and the same 13 detectors run against them unchanged.

---

## Optional Integrations

### AI executive reports (Ollama)

```bash
ollama pull llama3.2      # ~2 GB download
ollama serve              # keep running in its own terminal
```

Verify with `curl http://localhost:11434/api/tags`, then run a scan — the AI Executive Report panel populates automatically. The scanner is fully functional without Ollama.

### Slack / Microsoft Teams alerts

Critical and High findings can be pushed to chat in real time. Set either or both in `backend/.env` (HTTPS is enforced — the senders refuse plain-HTTP URLs):

```ini
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TEAMS_WEBHOOK_URL=https://...   # Teams *Workflows* webhook (classic
                                # Office 365 connectors were retired in 2026)
```

---

## API Reference

All endpoints are prefixed with `/api/v1` and (except `/health` and login) require an authenticated session. Interactive docs are served at `http://localhost:8000/docs` in development (disabled when `ENVIRONMENT=production`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `POST` | `/api/v1/auth/login` | Log in — sets httpOnly JWT cookie (rate-limited 5/min/IP) |
| `GET` | `/api/v1/auth/me` | Current session info |
| `POST` | `/api/v1/auth/logout` | Clear session cookie |
| `POST` | `/api/v1/scans` | Trigger a scan (returns 202, runs in background) |
| `GET` | `/api/v1/scans` | Paginated scan history |
| `GET` | `/api/v1/scans/{id}/status` | Poll scan status + results |
| `GET` | `/api/v1/scans/{id}/findings` | Findings for one scan |
| `GET` | `/api/v1/dashboard` | Aggregated summary for the landing page |
| `GET` | `/api/v1/analytics/risk-trend` | Risk score over time |
| `GET` | `/api/v1/analytics/mitre-coverage` | Findings per MITRE ATT&CK technique |
| `GET` | `/api/v1/analytics/alert-type-breakdown` | Findings per detector |
| `GET` | `/api/v1/analytics/scan-stats` | Aggregate scan statistics |
| `GET` | `/api/v1/users` | Per-user finding summary |
| `GET` | `/api/v1/users/{username}/findings` | Findings for one user |
| `GET` | `/api/v1/s3-reports` | List archived scan reports in S3 |
| `GET` | `/api/v1/s3-reports/compare` | Diff two archived reports |
| `GET` | `/api/v1/s3-reports/{key}` | Fetch one archived report |
| `PATCH` | `/api/v1/findings/{id}/acknowledge` | Acknowledge a finding (with note) |
| `DELETE` | `/api/v1/findings/{id}/acknowledge` | Revert an acknowledgement |

---

## Configuration

All configuration is via environment variables in `backend/.env` (see `backend/.env.example` for a documented template).

### Core

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET_KEY` | — *(required)* | Secret for signing session JWTs — long random string |
| `ENVIRONMENT` | `development` | `production` disables `/docs` and enables the `Secure` cookie flag |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Session JWT lifetime |
| `USE_REAL_AWS` | `false` | `true` scans a live AWS account instead of mock data |
| `AWS_DEFAULT_REGION` | — | AWS region for boto3 clients |
| `REPORT_BUCKET` | — | S3 bucket holding archived scan reports |
| `S3_REQUIRE_ENCRYPTION` | `false` | `true` refuses to serve S3 reports not encrypted at rest |

### Detector thresholds

| Variable | Default | Description |
|---|---|---|
| `KEY_ROTATION_DAYS` | `90` | Max API key age before alert |
| `PASSWORD_MAX_AGE_DAYS` | `90` | Max password age before alert |
| `STALE_ACCOUNT_DAYS` | `60` | Days inactive before stale-account alert |
| `DORMANT_ADMIN_DAYS` | `30` | Days inactive for privileged accounts |
| `MAX_ACTIVE_KEYS_PER_USER` | `1` | Max active API keys per user |
| `BRUTE_FORCE_THRESHOLD` | `10` | Failed logins per 24 h before alert |
| `BUSINESS_HOURS_START` / `BUSINESS_HOURS_END` | `8` / `18` | Business-hours window (UTC) for off-hours detection |

### Integrations

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2` | Model for AI reports |
| `OLLAMA_TIMEOUT_SEC` | `45` | LLM request timeout |
| `SLACK_WEBHOOK_URL` | — | Slack Incoming Webhook (HTTPS only) |
| `TEAMS_WEBHOOK_URL` | — | Teams Workflows webhook (HTTPS only) |
| `DASHBOARD_URL` | — | Link embedded in chat alerts |

> **Frontend:** the only frontend variable is `VITE_API_BASE_URL` (empty = use the Vite dev proxy). Vite bakes every `VITE_*` value into the public JS bundle at build time — **never** put secrets behind a `VITE_` prefix.

---

## Testing

```bash
cd backend
venv\Scripts\activate
pytest
```

The suite (`backend/tests/`, 12 modules) covers authentication, scan routes, the scan worker, analytics, boto3/CloudTrail inventory, S3 report handling, notifications, and incident explanation.

---

## AWS Lambda Deployment

The same detection engine runs as a scheduled Lambda for unattended daily scans:

- `lambda-deployment/lambda_function.py` imports the shared scanner, swaps in the real boto3 inventory fetcher, runs all checks, and writes JSON + text reports to `REPORT_BUCKET`.
- Triggered by an **EventBridge** rule (`rate(1 day)`).
- `lambda-deployment/iam_execution_role.json` defines the least-privilege execution role.
- `lambda-deployment/deploy.sh` builds and ships the deployment package.

Improvements made to the local engine (new detectors, tuned scores, MITRE mappings) are picked up by the Lambda on the next deploy with no Lambda-specific changes.

---

## Security

See **[SECURITY.md](SECURITY.md)** for the full security posture: implemented controls (httpOnly JWT cookies, bcrypt, login rate limiting, S3 key validation, HTTPS-only webhooks), deliberately accepted risks with rationale, and operator constraints.

Golden rules:

- **Never commit `.env` files** — copy `backend/.env.example` and fill in values locally. Secrets stay out of Git.
- Scanner runtime state (`backend/scanner/state/`, the SQLite DB, scanner logs, scan reports) contains real IAM inventory data and is gitignored — keep it that way.
- Do not expose ports 8000/5173 to a public network without a reverse proxy and TLS.

---

## Acknowledgements

Built as a Bachelor's-level cloud security final-year project. Detection logic informed by AWS Security Hub, Microsoft Defender for Cloud, CIS Benchmarks for IAM, and the MITRE ATT&CK framework.
