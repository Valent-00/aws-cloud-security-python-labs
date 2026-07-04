# 🛡️ IAM Security Scanner

A full-stack **Cloud Identity & Access Management (IAM) Security Posture Scanner** with an AI-powered incident reporting dashboard.



- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Enabling AI Reports (Ollama)](#enabling-ai-reports-ollama)
- [API Reference](#api-reference)
- [Security Detectors](#security-detectors)
- [Configuration](#configuration)
- [Known Limitations](#known-limitations)

---

## Overview

This project simulates a production-grade **Cloud Security Posture Management (CSPM)** tool, covering the full pipeline from telemetry ingestion to incident response. It was built as a Bachelor's-level cybersecurity portfolio project.

The scanner monitors IAM user accounts for:
- Credential hygiene issues (MFA, key rotation, password age)
- Behavioural anomalies (off-hours logins, geo anomalies, brute force)
- Privilege risks (dormant admins, wildcard permissions, root usage)
- Configuration drift (role escalation, MFA regression between scans)

All findings are deduplicated across runs, severity-classified, and surfaced in a React dashboard with inline analyst workflow (acknowledge / review).

---

## Features

### Detection Engine (13 checks)

| Check | Severity | Description |
|---|---|---|
| MFA Disabled | Medium–High | Account has no multi-factor authentication |
| Stale Key | Low–Critical | API key older than rotation policy limit |
| Never Used Key | Low | Key created but never called — orphaned attack surface |
| Multiple Active Keys | Low–Medium | User holds more than the allowed number of keys |
| No Password Rotation | Medium–Critical | Password exceeds maximum age policy |
| Dormant Admin | High | Privileged account with no login in N days |
| Stale Account | Low–Medium | Any account inactive beyond threshold |
| Disabled Account With Key | Medium–High | Disabled account still holds an active API key |
| Wildcard Permission | High | IAM policy contains `*:*` — violates least privilege |
| Root Account Used | Critical | Cloud root account logged in recently |
| Brute Force Indicator | Medium–High | Failed logins exceed threshold in 24h |
| Off-Hours Login | Low | Login outside configured business hours |
| Geo Anomaly | High | Login from a country not in the user's baseline |

### Platform Features

- **Severity bands** — Critical / High / Medium / Low / Info with SLA targets
- **Alert deduplication** — SHA-256 fingerprinting suppresses repeat alerts
- **Field-level drift detection** — catches MFA flips, role escalations between scans
- **Async scanning** — POST triggers background job, frontend polls for completion
- **AI executive reports** — Ollama LLM generates professional incident summaries
- **Analyst workflow** — acknowledge findings with notes, revert acknowledgements
- **Structured JSON export** — machine-readable output for SIEM ingestion
- **Scan history** — full audit trail of every scan run with severity breakdown

---

## Tech Stack

### Backend
| Technology | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Core language |
| FastAPI | 0.115 | REST API framework |
| Uvicorn | 0.30 | ASGI server |
| SQLAlchemy | 2.0 | ORM + database abstraction |
| SQLite | built-in | Persistent storage (zero config) |
| Pydantic | 2.9 | Request/response validation |
| python-dotenv | 1.0 | Environment variable management |
| Requests | 2.32 | Ollama HTTP client |

### Frontend
| Technology | Version | Purpose |
|---|---|---|
| React | 18.3 | UI framework |
| Vite | 5.4 | Build tool and dev server |
| Tailwind CSS | 3.4 | Utility-first styling |
| React Router | 6.26 | Client-side routing |
| Axios | 1.7 | HTTP client |
| Recharts | 2.12 | Chart components |

### AI / LLM
| Technology | Purpose |
|---|---|
| Ollama | Local LLM inference server |
| llama3.2 | Model used for incident report generation |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Frontend                          │
│  Dashboard │ Findings │ Users │ Scan History                │
│            (Vite dev server — port 5173)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP (Axios)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                          │
│                    (Uvicorn — port 8000)                    │
│                                                             │
│   POST /api/v1/scans ──► Background Thread                 │
│   GET  /api/v1/scans/{id}/status                           │
│   GET  /api/v1/dashboard                                   │
│   GET  /api/v1/findings                                    │
│   PATCH /api/v1/findings/{id}/acknowledge                  │
└──────┬───────────────────────────┬──────────────────────────┘
       │ SQLAlchemy                │ HTTP
       ▼                           ▼
┌─────────────┐           ┌─────────────────┐
│   SQLite    │           │   Ollama LLM    │
│  Database   │           │  (port 11434)   │
│             │           │  llama3.2 model │
│ scan_runs   │           └─────────────────┘
│ findings    │
│ alert_state │
└─────────────┘
       ▲
       │
┌─────────────────────────────────────────────────────────────┐
│              IAM Scanner Engine (Python)                    │
│                                                             │
│  fetch_cloud_inventory()   ← swap for real SDK here        │
│  run_all_checks()                                           │
│  ├── 13 detector functions                                  │
│  ├── detect_field_level_drift()                             │
│  └── deduplicate_findings()   ← SHA-256 fingerprinting     │
│  generate_ai_summary()     ← calls Ollama                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
iam-scanner/
│
├── .gitignore
├── README.md
│
├── backend/
│   ├── main.py                     # FastAPI app — all routes
│   ├── requirements.txt
│   ├── .env.example                # Copy to .env and configure
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   └── api_mock_scanner.py     # Detection engine (13 checks)
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py             # SQLAlchemy models + DB init
│   │
│   └── schemas/
│       ├── __init__.py
│       └── schemas.py              # Pydantic request/response schemas
│
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js              # Dev proxy → backend port 8000
    ├── tailwind.config.js
    ├── postcss.config.js
    │
    └── src/
        ├── App.jsx                 # Root component + router + nav
        ├── main.jsx
        ├── index.css
        │
        ├── api/
        │   └── client.js           # Axios instance + all API calls
        │
        ├── components/
        │   ├── SeverityBadge.jsx   # Colour-coded severity pill
        │   ├── FindingCard.jsx     # Single finding with ack action
        │   ├── ScanTrigger.jsx     # Run Scan button + polling
        │   └── AiReportPanel.jsx   # Collapsible AI report
        │
        └── pages/
            ├── Dashboard.jsx       # Landing page — severity cards
            ├── Findings.jsx        # Full findings table + filter
            ├── UserDetail.jsx      # Per-user drill-down
            └── ScanHistory.jsx     # Past scans + audit trail
```

---

## Prerequisites

Before you begin, ensure you have:

| Requirement | Version | Check command |
|---|---|---|
| Python | 3.10 or above | `python --version` |
| Node.js | 18 or above | `node --version` |
| npm | 8 or above | `npm --version` |
| Git | Any | `git --version` |
| Ollama (optional) | Any | `ollama --version` |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/iam-scanner.git
cd iam-scanner
```

### 2. Backend setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create your .env file
cp .env.example .env
```

### 3. Frontend setup

```bash
cd ../frontend

# Install dependencies
npm install

# Create frontend env file
echo "VITE_API_BASE_URL=" > .env
```

---

## Running the Application

You need **two terminals** running simultaneously (three if using Ollama).

### Terminal 1 — Backend

```bash
cd backend
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

uvicorn main:app --reload --port 8000
```

Expected output:
```
INFO: Uvicorn running on http://127.0.0.1:8000
INFO: Application startup complete.
```

### Terminal 2 — Frontend

```bash
cd frontend
npm run dev
```

Expected output:
```
VITE v5.x  ready in Xms
➜  Local: http://localhost:5173/
```

### Open the dashboard

Navigate to: **http://localhost:5173**

Click **Run Scan Now** on the Dashboard to trigger your first scan.

---

## Enabling AI Reports (Ollama)

AI-generated executive reports are optional. The scanner works fully without them.

### Step 1 — Install Ollama

Download from [https://ollama.com/download](https://ollama.com/download) and install.

### Step 2 — Pull the model

```bash
ollama pull llama3.2
```

This downloads approximately 2GB. Wait for it to complete.

### Step 3 — Start the Ollama server

```bash
# Terminal 3 — keep this open
ollama serve
```

### Step 4 — Verify

```cmd
curl http://localhost:11434/api/tags
```

Should return a JSON list of models. Now run a scan from the dashboard — the
🤖 AI Executive Report panel will populate after the scan completes.

---

## API Reference

All endpoints are prefixed with `/api/v1`. Interactive documentation is available at `http://localhost:8000/docs` when the backend is running.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `POST` | `/api/v1/scans` | Trigger a new scan (returns 202) |
| `GET` | `/api/v1/scans` | List scan history (paginated) |
| `GET` | `/api/v1/scans/{id}/status` | Poll scan status + results |
| `GET` | `/api/v1/scans/{id}/findings` | All findings for one scan |
| `GET` | `/api/v1/dashboard` | Aggregated summary for landing page |
| `GET` | `/api/v1/users` | Per-user finding summary |
| `GET` | `/api/v1/users/{username}/findings` | All findings for one user |
| `PATCH` | `/api/v1/findings/{id}/acknowledge` | Acknowledge a finding |
| `DELETE` | `/api/v1/findings/{id}/acknowledge` | Remove acknowledgement |

---

## Security Detectors

To connect this scanner to a real cloud provider, replace the body of
`fetch_cloud_inventory()` in `backend/scanner/api_mock_scanner.py` with
your real SDK call:

```python
# AWS example (requires boto3)
import boto3

def fetch_cloud_inventory() -> list[UserRecord]:
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    # ... map to UserRecord schema
    return records

# GCP example (requires google-cloud-iam)
# Azure example (requires azure-identity)
```

The rest of the scanner — all 13 detectors, deduplication, scoring, AI
reports, and the dashboard — require no changes.

---

## Configuration

All configuration is via environment variables in `backend/.env`.

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2` | LLM model name |
| `OLLAMA_TIMEOUT_SEC` | `45` | Request timeout in seconds |
| `KEY_ROTATION_DAYS` | `90` | Max API key age before alert |
| `PASSWORD_MAX_AGE_DAYS` | `90` | Max password age before alert |
| `STALE_ACCOUNT_DAYS` | `60` | Days inactive before stale account alert |
| `DORMANT_ADMIN_DAYS` | `30` | Days inactive for privileged accounts |
| `MAX_ACTIVE_KEYS_PER_USER` | `1` | Max active API keys per user |
| `BRUTE_FORCE_THRESHOLD` | `10` | Failed logins per 24h before alert |
| `BUSINESS_HOURS_START` | `8` | Start of business hours (UTC) |
| `BUSINESS_HOURS_END` | `18` | End of business hours (UTC) |

---

## Known Limitations

- **Mock data only** — `fetch_cloud_inventory()` returns hardcoded users. Connect a real cloud SDK to scan live accounts.
- **No authentication** — the dashboard has no login. Do not expose port 5173 or 8000 to a public network.
- **Single-user** — no multi-tenancy or role-based access control.
- **SQLite** — suitable for development and portfolio use. Replace with PostgreSQL for production workloads.
- **No scheduled scanning** — scans run on-demand via the dashboard button.

---

## Acknowledgements

Built as part of a Bachelor's-level cloud security portfolio project. Detection logic is based on real-world CSPM frameworks including AWS Security Hub, Microsoft Defender for Cloud, and CIS Benchmarks for IAM.