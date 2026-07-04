"""
scripts/create_analyst.py
==========================
Provision a SOC analyst login account.

Why a script instead of a sign-up endpoint
-------------------------------------------
There is deliberately no POST /api/v1/auth/register route. A security
scanner that lets anyone self-enroll as an analyst would undermine the
access control it's meant to demonstrate — accounts are provisioned
out-of-band by whoever already has shell access to the server, the same
way you'd provision a break-glass account on a real SOC platform.

Usage
-----
    cd backend
    python scripts/create_analyst.py <username> [--role admin]

The password is prompted for interactively (hidden input, asked twice).
Passing it on the command line is still possible via --password for
non-interactive provisioning, but is discouraged: argv values end up in
shell history and are visible to other local users via process listings.

Examples
--------
    python scripts/create_analyst.py alice --role admin
    python scripts/create_analyst.py bob

Re-running with an existing username updates that user's password instead
of failing — convenient if you forget a password during a demo, while
still requiring shell access to do it.
"""
import argparse
import getpass
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BACKEND_DIR)

from auth.auth import hash_password                                   # noqa: E402
from models.database import AnalystUser, SessionLocal, init_db, utc_now  # noqa: E402


def create_or_update_analyst(username: str, password: str, role: str) -> None:
    """Create a new AnalystUser, or update the password/role of an existing one."""
    init_db()
    db = SessionLocal()
    try:
        user = db.query(AnalystUser).filter(AnalystUser.username == username).first()
        if user:
            user.hashed_password = hash_password(password)
            user.role            = role
            user.is_active       = True
            db.commit()
            print(f"Updated existing analyst '{username}' (role={role}).")
        else:
            db.add(AnalystUser(
                username=username,
                hashed_password=hash_password(password),
                role=role,
                is_active=True,
                created_at=utc_now(),
            ))
            db.commit()
            print(f"Created analyst '{username}' (role={role}).")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a SOC analyst login account.")
    parser.add_argument("username", help="Login username")
    parser.add_argument(
        "--password",
        default=None,
        help=(
            "Login password. Omit to be prompted securely (recommended) — "
            "passwords passed as arguments leak into shell history and "
            "process listings."
        ),
    )
    parser.add_argument(
        "--role",
        choices=["analyst", "admin"],
        default="analyst",
        help="Account role (default: analyst)",
    )
    args = parser.parse_args()

    if args.password is None:
        first  = getpass.getpass("Password (hidden): ")
        second = getpass.getpass("Confirm password: ")
        if first != second:
            print("Passwords do not match — no account created.", file=sys.stderr)
            sys.exit(1)
        args.password = first
    else:
        print(
            "Warning: password supplied via --password is visible in shell "
            "history and process listings. Prefer omitting it to be prompted.",
            file=sys.stderr,
        )

    # Shell quoting mistakes (e.g. a trailing space left inside quotes in
    # PowerShell: "mypassword "--role) silently bake invisible whitespace
    # into the password — the account is created "successfully" with a
    # password nobody can actually type into the login form. Stripping
    # here keeps this consistent with LoginRequest's validator, which
    # strips the same way on the login side.
    username = args.username.strip()
    password = args.password.strip()

    if username != args.username or password != args.password:
        print(
            "Note: leading/trailing whitespace was trimmed from the username "
            "and/or password you passed in (often caused by shell quoting, "
            "e.g. a trailing space left inside quotes in PowerShell).",
            file=sys.stderr,
        )

    if len(password) < 8:
        print("Refusing to create an account with a password under 8 characters.", file=sys.stderr)
        sys.exit(1)

    create_or_update_analyst(username, password, args.role)


if __name__ == "__main__":
    main()