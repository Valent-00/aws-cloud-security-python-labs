# Security Notes — IAM Security Scanner v2.1

This file records the security posture decisions from the 2026-07
pre-deployment review: what was fixed, what is deliberately accepted,
and the constraints an operator must know before deploying.

## Implemented controls (summary)

| Control | Where |
|---|---|
| JWT delivered only via httpOnly cookie (never in JSON body / localStorage) | `backend/auth/auth.py`, Fix #1 |
| `/docs`, `/redoc`, `/openapi.json` disabled when `ENVIRONMENT=production` | `backend/main.py`, Fix #2 |
| Login rate-limited to 5/minute per IP (slowapi) | `backend/main.py`, Fix #3 |
| Token expiry default 480 → 60 minutes | `backend/auth/auth.py`, Fix #4 |
| Webhook senders refuse non-HTTPS URLs | `shared/notifications.py`, Fix H-2 |
| S3 report keys validated against traversal / prefix escape | `backend/cloud/s3_reports.py`, Fix M-3 |
| Optional fail-closed S3 encryption check (`S3_REQUIRE_ENCRYPTION`) | Fix H-3 |
| Passwords hashed with bcrypt; no self-registration endpoint | `backend/auth/auth.py` |
| Generic 401 on login (no username enumeration) | `backend/main.py` |

## Accepted risks

### M-1 — No server-side token revocation (ACCEPTED)

Logout clears the httpOnly cookie, but the JWT itself remains
cryptographically valid until it expires. A token stolen before logout
can therefore be replayed for the remainder of its lifetime.

**Why accepted:** sessions are stateless by design (no server-side
session store). The realistic exposure window is capped at 60 minutes
by Fix #4, the token can only be exfiltrated via full compromise of the
browser or a network position that defeats TLS (both out of scope for
this threat model), and it is delivered in an httpOnly cookie that
scripts cannot read. Building a denylist or token-version store would
reintroduce the state the stateless design avoids — disproportionate
for this project's scope.

**Compensating controls:** 60-minute expiry; httpOnly + SameSite=Lax +
Secure (in production) cookie; login rate limiting.

**Revisit if:** token lifetime is ever raised, an admin role gains
destructive capabilities, or the app is deployed for real multi-analyst
production use. The cheapest upgrade path then is a `token_version`
column on `AnalystUser` checked in `get_current_user()`.

## Operator awareness

### L-1 — Scanner runtime state must never be committed (FIXED 2026-07-04)

`backend/scanner/state/baseline_iam.json` is a snapshot of the real IAM
inventory (usernames, attached permissions, login metadata) and the
SQLite DB / scanner logs contain the same class of data. These were
previously tracked; they are now removed from the index and covered by
`.gitignore` (which was also rewritten — the old file was saved as
UTF-16, an encoding Git cannot parse, so **every rule in it was being
silently ignored**). Note that previously committed copies still exist
in Git history (see incident note below).

### L-2 — Vite bakes `VITE_*` variables into the public bundle

Any variable prefixed `VITE_` in `frontend/.env` is string-substituted
into the compiled JavaScript at build time and is readable by anyone
who loads the app. This is how Vite works, not a bug.

**Rule: only non-secret configuration may ever use the `VITE_` prefix.**
The only variable currently used is `VITE_API_BASE_URL`
(`frontend/src/api/client.js`), which is a public URL — fine. API keys,
webhook URLs, and anything AWS-related belong in `backend/.env` only,
where they stay server-side.

## Incident note — committed secrets (2026-07-04)

`backend/.env` was tracked in Git and pushed to the public GitHub
remote, exposing the then-current `JWT_SECRET_KEY` (plus the AWS
account ID and report bucket name). Response taken:

1. The JWT secret was **rotated** — the leaked value no longer signs or
   verifies anything.
2. `backend/.env`, `frontend/.env`, the SQLite database, scanner logs,
   and the IAM baseline were removed from the Git index; `.gitignore`
   was rewritten in UTF-8 so it actually takes effect.
3. The **old values remain in Git history** on GitHub. The rotated
   secret is worthless there, but the AWS account ID and bucket name
   are still visible. Account IDs are not credentials and bucket access
   is governed by IAM policy, so this is accepted as low risk. If you
   want history scrubbed anyway, use `git filter-repo` (or GitHub
   support for cached views) — a force-push rewrite is the cost.

**Never commit `.env` files. Copy `backend/.env.example` and fill in
values locally.**
