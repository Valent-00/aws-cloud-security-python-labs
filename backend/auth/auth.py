"""
auth.py
=======
Authentication for the IAM Security Scanner API.

Why this exists
----------------
Every route in this API was, until now, reachable by anyone who could
reach the port — including triggering scans, reading every finding, and
acknowledging incidents with no record of who did it. For a tool whose
entire purpose is securing access control on OTHER systems, shipping
with none of its own is the kind of gap a security reviewer flags first.

Design
------
  * Passwords are hashed with bcrypt (via the `bcrypt` library directly —
    not passlib, which has had version-compatibility friction with recent
    bcrypt releases). Never store or log a plaintext password.
  * Sessions are stateless JSON Web Tokens (HS256), so the API doesn't
    need a server-side session store. Tokens carry username + role and
    expire after ACCESS_TOKEN_EXPIRE_MINUTES.
  * Accounts are provisioned out-of-band via scripts/create_analyst.py —
    there is deliberately NO open self-registration endpoint. A SOC tool
    that lets anyone sign themselves up as an analyst would defeat its
    own purpose.
  * get_current_user() is a FastAPI dependency — add it to any route that
    should require login. require_role() builds on it for routes that
    should additionally require a specific role (e.g. "admin").

Security fix — JWT delivery (2026-07)
--------------------------------------
Previously the JWT was returned in the login response body and expected
back via an "Authorization: Bearer <token>" header, which meant the
frontend had to store it somewhere JavaScript could read — localStorage.
Any successful XSS injection anywhere in the app could then read that
token wholesale and impersonate the analyst indefinitely.

The token is now delivered exclusively via an httpOnly cookie:
  * set_auth_cookie() is called by the login route to attach it to the
    response — JavaScript can never read this cookie's value, even via
    document.cookie, because httponly=True.
  * get_current_user() now reads the token from that cookie instead of
    an Authorization header. The OAuth2PasswordBearer scheme has been
    removed — this also means Swagger's "Authorize" button no longer
    works for manual testing (see SQA notes for how to test instead).
  * clear_auth_cookie() is called by the logout route to invalidate the
    session client-side (there is no server-side revocation list — the
    token remains cryptographically valid until it expires naturally,
    which is why Fix #4 below matters).

Secret key handling
--------------------
JWT_SECRET_KEY should always be set via environment variable in any
real deployment. If it is unset, a fixed insecure fallback is used SO
THE APP STILL RUNS for local FYP demos, but a loud warning is logged
every startup. Never rely on the fallback outside local development —
anyone who reads this source file can forge tokens signed with it.
"""

import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Optional
load_dotenv()

import bcrypt
import jwt
from fastapi import Cookie, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from models.database import AnalystUser, get_db

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_INSECURE_DEV_DEFAULT = "insecure-dev-only-secret-do-not-use-in-production"

SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", _INSECURE_DEV_DEFAULT)
ALGORITHM: str = "HS256"

# Fix #4: default reduced from 480 to 60 minutes. Still overridable via
# .env for deployments with different risk tolerance, but the fallback
# a developer gets with a bare `git clone` is now the safer one.
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

if SECRET_KEY == _INSECURE_DEV_DEFAULT:
    import logging
    logging.getLogger("iam_scanner.auth").warning(
        "JWT_SECRET_KEY is not set — using an insecure built-in default. "
        "Tokens signed with this key can be forged by anyone who has read "
        "this source file. Set JWT_SECRET_KEY in your .env before any "
        "real deployment."
    )

# ---------------------------------------------------------------------------
# Cookie configuration — Fix #1
# ---------------------------------------------------------------------------
# ENVIRONMENT drives both this and the /docs toggle in main.py, so the two
# stay in lockstep: a deployment that hides its API docs also gets a
# Secure cookie, and a local dev box gets neither.
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()

COOKIE_NAME: str = "iam_scanner_token"
COOKIE_SECURE: bool = ENVIRONMENT == "production"   # HTTPS-only in prod
COOKIE_SAMESITE: str = "lax"                        # survives the Vite dev proxy
COOKIE_PATH: str = "/"


def set_auth_cookie(response: Response, token: str) -> None:
    """
    Attach the JWT to the response as an httpOnly cookie.

    Called by the login route. The token is never present in the JSON
    response body — only in this Set-Cookie header, which JavaScript
    cannot read (httponly=True blocks document.cookie access).

    Args:
        response: The FastAPI Response object for the current request.
        token:    The signed JWT to store.
    """
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path=COOKIE_PATH,
    )


def clear_auth_cookie(response: Response) -> None:
    """
    Remove the auth cookie from the browser.

    Called by the logout route. Deletion attributes (path, samesite,
    secure) must match what was used to set the cookie, or some
    browsers will silently ignore the delete.

    Args:
        response: The FastAPI Response object for the current request.
    """
    response.delete_cookie(
        key=COOKIE_NAME,
        path=COOKIE_PATH,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
    )


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password with bcrypt for storage.

    Args:
        plain_password: The password as entered by the user.

    Returns:
        A bcrypt hash string, safe to store in the database.
    """
    hashed: bytes = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Check a plaintext password against a stored bcrypt hash.

    Args:
        plain_password:  Password supplied at login.
        hashed_password: Hash previously produced by hash_password().

    Returns:
        True if the password matches, False otherwise (never raises on
        a wrong password — only on a malformed hash).
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT issuance / verification
# ---------------------------------------------------------------------------

def create_access_token(username: str, role: str) -> str:
    """
    Issue a signed JWT for an authenticated user.

    Args:
        username: The analyst's username — stored in the "sub" claim.
        role:     The analyst's role (e.g. "analyst", "admin").

    Returns:
        Encoded JWT string. As of Fix #1, this is placed in an httpOnly
        cookie by the caller (via set_auth_cookie) rather than returned
        to the client in a JSON body.
    """
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expires_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Verify and decode a JWT.

    Args:
        token: The raw JWT string, read from the auth cookie.

    Returns:
        The decoded claims dict ({"sub": ..., "role": ..., "exp": ...}).

    Raises:
        HTTPException(401): If the token is expired, malformed, or has
                             an invalid signature.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired — please log in again.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies — attach to any route that needs auth
# ---------------------------------------------------------------------------

def get_current_user(
    access_token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    db: Session = Depends(get_db),
) -> AnalystUser:
    """
    Resolve the authenticated AnalystUser from the request's auth cookie.

    Fix #1: previously read from an "Authorization: Bearer <token>"
    header via OAuth2PasswordBearer. Now reads the httpOnly cookie set
    by /auth/login directly — the browser attaches it automatically on
    every same-origin (or proxied) request, so the frontend never
    handles the raw token at all.

    Usage:
        @app.get("/example")
        def example(user: AnalystUser = Depends(get_current_user)):
            ...

    Raises:
        HTTPException(401): Cookie missing/invalid/expired, or the user
                             it names no longer exists or was deactivated.
    """
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
        )

    claims = decode_access_token(access_token)
    username: Optional[str] = claims.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid authentication token.")

    user = db.query(AnalystUser).filter(AnalystUser.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account not found or deactivated.")
    return user


def require_role(*allowed_roles: str):
    """
    Build a dependency that requires the current user to hold one of
    the given roles, in addition to being authenticated.

    Usage:
        @app.post("/admin-only", dependencies=[Depends(require_role("admin"))])
        def admin_only(): ...

    Args:
        *allowed_roles: One or more role strings that may access the route.

    Returns:
        A FastAPI dependency callable.
    """
    def _check(user: AnalystUser = Depends(get_current_user)) -> AnalystUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {', '.join(allowed_roles)}.",
            )
        return user
    return _check