"""
conftest.py
===========
Shared pytest fixtures for the IAM Security Scanner test suite.

This file lives in backend/tests/ and pytest auto-discovers it — any
fixture defined here is available to every test file in this directory
without an import.
"""
import sys
import os
from pathlib import Path

import pytest

# Make the backend package importable when running `pytest` from
# backend/ (mirrors how the real app and cloudtrail_inventory.py are
# already laid out on disk).
BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

# boto3_inventory.py and lambda_function.py live in lambda-deployment/,
# not backend/ — they were built for the Lambda packaging pipeline and
# were never moved. Rather than duplicate those files into backend/
# (you already have api_mock_scanner.py duplicated between backend/
# and lambda-deployment/ as it is — one more copy just multiplies that
# sync problem), point the test path at where they actually are.
LAMBDA_DEPLOYMENT_DIR = BACKEND_DIR.parent / "lambda-deployment"
if LAMBDA_DEPLOYMENT_DIR.exists():
    sys.path.insert(0, str(LAMBDA_DEPLOYMENT_DIR))


# ===========================================================================
# API-level test infrastructure (main.py routes, auth.py, models/database.py)
# ===========================================================================
#
# database.py creates its engine/SessionLocal at IMPORT time, bound to the
# real file at backend/data/iam_scanner.db. We never want tests touching
# that file. The fix: monkeypatch models.database.engine/SessionLocal to
# point at an in-memory SQLite DB *before* anything (including main.py's
# own lifespan startup) calls them — get_db() and _run_scan_worker() both
# read SessionLocal as a module-level name at call time, not at import
# time, so the patch reaches both code paths even though one goes through
# FastAPI's Depends() and the other calls SessionLocal() directly.
#
# Plain "sqlite:///:memory:" is NOT enough on its own: SQLAlchemy's default
# pooling hands out a fresh connection per checkout, and each connection to
# ":memory:" is its OWN separate empty database — a session in one thread
# can't see tables created in another. StaticPool pins every checkout to
# the exact same underlying connection, which is what actually makes a
# single shared in-memory DB usable across the test thread and the
# background scan-worker thread.
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import models.database as database_module


@pytest.fixture
def test_engine(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(database_module, "engine", engine)

    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(database_module, "SessionLocal", TestSessionLocal)

    # Create tables explicitly here rather than relying on main.py's
    # lifespan (init_db()) to do it — several tests use db_session
    # directly without ever spinning up a TestClient, so that lifespan
    # event would simply never fire for them and every query would hit
    # "no such table".
    database_module.Base.metadata.create_all(bind=engine)

    yield engine


@pytest.fixture
def db_session(test_engine):
    """A session bound to the patched test engine, for direct fixture
    setup (inserting rows a test needs without going through the API)."""
    Session = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def fake_analyst_user(db_session):
    """A real AnalystUser row in the test DB, with a real bcrypt hash —
    used both directly (login tests) and via dependency override (every
    other protected-route test)."""
    from auth.auth import hash_password
    from models.database import AnalystUser, utc_now

    user = AnalystUser(
        username="test-analyst",
        hashed_password=hash_password("correct-password"),
        role="analyst",
        is_active=True,
        created_at=utc_now(),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def client(test_engine, db_session, fake_analyst_user):
    """
    TestClient with get_db AND get_current_user overridden — use this
    for testing route LOGIC without needing a real bearer token on
    every single test.
    """
    import main
    from auth.auth import get_current_user
    from models.database import get_db

    def override_get_db():
        yield db_session

    def override_get_current_user():
        return fake_analyst_user

    main.app.dependency_overrides[get_db] = override_get_db
    main.app.dependency_overrides[get_current_user] = override_get_current_user

    with TestClient(main.app) as c:
        yield c

    main.app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    """Fix #3 rate-limits /auth/login to 5/minute per IP. The counter
    lives in module-level app.state.limiter storage, so login attempts
    accumulate ACROSS tests — without this reset, whichever login test
    happens to run sixth within a minute fails with a spurious 429."""
    import main
    main.app.state.limiter.reset()
    yield


@pytest.fixture
def client_real_auth(test_engine, db_session):
    """
    TestClient with ONLY get_db overridden — auth.get_current_user is
    NOT bypassed. Use this for testing that protected routes actually
    reject requests with no/invalid token, and for the real login flow.
    """
    import main
    from models.database import get_db

    def override_get_db():
        yield db_session

    main.app.dependency_overrides[get_db] = override_get_db

    with TestClient(main.app) as c:
        yield c

    main.app.dependency_overrides.clear()


@pytest.fixture
def sample_credential_report_csv() -> bytes:
    """
    A minimal but realistic IAM credential report CSV, as bytes — this
    is exactly the shape iam.get_credential_report()["Content"] returns
    in real AWS, which is what _generate_credential_report() decodes.
    """
    return (
        b"user,arn,user_creation_time,password_enabled,password_last_used,"
        b"password_last_changed,mfa_active,access_key_1_active\n"
        b"valent-admin,arn:aws:iam::501421114742:user/valent-admin,"
        b"2026-06-20T00:00:00+00:00,true,2026-06-26T00:00:00+00:00,"
        b"2026-06-20T00:00:00+00:00,false,true\n"
        b"<root_account>,arn:aws:iam::501421114742:root,"
        b"2026-06-25T08:09:00+00:00,true,2026-06-26T06:50:58+00:00,"
        b"not_supported,true,not_supported\n"
    )


@pytest.fixture
def real_root_login_event() -> dict:
    """
    The actual root ConsoleLogin event pulled from a real account during
    this project's own incident-investigation workflow. Using a real
    event (rather than an invented one) as a fixture means these tests
    are pinned to AWS's real response shape, not an assumed one.
    """
    return {
        "EventId": "ff0ea13c-2d97-4e3e-aae5-47f212766c35",
        "EventName": "ConsoleLogin",
        "Username": "root",
        "CloudTrailEvent": (
            '{"eventVersion":"1.11","userIdentity":{"type":"Root",'
            '"principalId":"501421114742",'
            '"arn":"arn:aws:iam::501421114742:root","accountId":'
            '"501421114742","accessKeyId":""},'
            '"eventTime":"2026-06-26T06:50:58Z",'
            '"eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin",'
            '"awsRegion":"us-east-1","sourceIPAddress":"115.164.36.147",'
            '"userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",'
            '"requestParameters":null,'
            '"responseElements":{"ConsoleLogin":"Success"},'
            '"additionalEventData":{"LoginTo":'
            '"https://console.aws.amazon.com/console/home",'
            '"MobileVersion":"No","MFAIdentifier":'
            '"arn:aws:iam::501421114742:mfa/Valent-Iphone",'
            '"MFAUsed":"Yes"},'
            '"eventID":"ff0ea13c-2d97-4e3e-aae5-47f212766c35"}'
        ),
    }