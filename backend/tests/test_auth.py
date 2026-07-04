"""
test_auth.py
============
Unit tests for auth.py — password hashing, JWT issuance/verification,
and the get_current_user / require_role FastAPI dependencies.

These test the real bcrypt and PyJWT logic directly, not mocked —
auth is the one file every protected route depends on, so it's worth
verifying for real rather than assuming it works.
"""
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from auth.auth import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    decode_access_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from models.database import AnalystUser, utc_now


# ===========================================================================
# Password hashing
# ===========================================================================

class TestPasswordHashing:
    def test_roundtrip_succeeds_with_correct_password(self):
        hashed = hash_password("correct-password")
        assert verify_password("correct-password", hashed) is True

    def test_fails_with_wrong_password(self):
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_is_never_the_plaintext(self):
        hashed = hash_password("correct-password")
        assert hashed != "correct-password"

    def test_two_hashes_of_same_password_differ(self):
        """bcrypt salts automatically — same password should never
        produce the same hash twice. If this ever fails, gensalt() has
        been replaced with something deterministic somewhere."""
        assert hash_password("same-password") != hash_password("same-password")


# ===========================================================================
# JWT issuance / verification
# ===========================================================================

class TestAccessTokens:
    def test_roundtrip_preserves_username_and_role(self):
        token = create_access_token(username="alice", role="analyst")
        claims = decode_access_token(token)
        assert claims["sub"] == "alice"
        assert claims["role"] == "analyst"

    def test_decode_raises_401_on_garbage_token(self):
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token("not.a.valid.jwt")
        assert exc_info.value.status_code == 401

    def test_decode_raises_401_on_expired_token(self):
        # Build an already-expired token directly, bypassing
        # create_access_token's fixed expiry window.
        expired_payload = {
            "sub": "alice",
            "role": "analyst",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(expired_token)
        assert exc_info.value.status_code == 401

    def test_decode_raises_401_on_wrong_signing_key(self):
        """A token signed with a different key (e.g. forged, or signed
        by a different environment's secret) must be rejected."""
        token = jwt.encode(
            {"sub": "alice", "role": "analyst",
             "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
            "a-completely-different-key",
            algorithm=ALGORITHM,
        )
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(token)
        assert exc_info.value.status_code == 401


# ===========================================================================
# get_current_user dependency
# ===========================================================================

class TestGetCurrentUser:
    def test_resolves_active_user_from_valid_token(self, db_session, fake_analyst_user):
        token = create_access_token(
            username=fake_analyst_user.username, role=fake_analyst_user.role
        )
        user = get_current_user(access_token=token, db=db_session)
        assert user.username == fake_analyst_user.username

    def test_rejects_deactivated_account(self, db_session):
        deactivated = AnalystUser(
            username="deactivated-user",
            hashed_password=hash_password("whatever"),
            role="analyst",
            is_active=False,
            created_at=utc_now(),
        )
        db_session.add(deactivated)
        db_session.commit()

        token = create_access_token(username="deactivated-user", role="analyst")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(access_token=token, db=db_session)
        assert exc_info.value.status_code == 401

    def test_rejects_token_for_user_that_no_longer_exists(self, db_session):
        token = create_access_token(username="ghost-user", role="analyst")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(access_token=token, db=db_session)
        assert exc_info.value.status_code == 401


# ===========================================================================
# require_role
# ===========================================================================

class TestRequireRole:
    def test_allows_matching_role(self, fake_analyst_user):
        fake_analyst_user.role = "admin"
        check = require_role("admin")
        # require_role()'s returned dependency takes the already-resolved
        # user via its own Depends(get_current_user) — calling it directly
        # with the user keyword bypasses needing a real token here, since
        # get_current_user's resolution path is already covered above.
        result = check(user=fake_analyst_user)
        assert result is fake_analyst_user

    def test_rejects_non_matching_role(self, fake_analyst_user):
        fake_analyst_user.role = "analyst"
        check = require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            check(user=fake_analyst_user)
        assert exc_info.value.status_code == 403