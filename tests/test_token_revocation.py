"""
Tests for backend/token_revocation.py — against a real Redis instance,
not a mock, since TTL expiry behavior is exactly the kind of thing a
mock could get subtly wrong.
"""
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
import redis

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only-never-use-in-production")

from backend.auth import create_access_token, decode_access_token
from backend.token_revocation import get_redis_client, is_revoked, revoke_token

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _redis_available() -> bool:
    try:
        client = redis.from_url(REDIS_URL)
        client.ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _redis_available(), reason="Redis not reachable")


@pytest.fixture()
def clean_redis():
    client = get_redis_client()
    yield client
    for key in client.scan_iter("revoked_token:*"):
        client.delete(key)


class TestTokenRevocation:
    def test_token_jti_is_unique_per_issuance(self):
        token_a = create_access_token("alice", "analyst")
        token_b = create_access_token("alice", "analyst")
        assert decode_access_token(token_a)["jti"] != decode_access_token(token_b)["jti"]

    def test_unrevoked_token_is_not_flagged(self, clean_redis):
        token = create_access_token("alice", "analyst")
        jti = decode_access_token(token)["jti"]
        assert is_revoked(jti) is False

    def test_revoked_token_is_flagged(self, clean_redis):
        token = create_access_token("alice", "analyst")
        payload = decode_access_token(token)
        revoke_token(payload["jti"], datetime.fromtimestamp(payload["exp"], tz=timezone.utc))
        assert is_revoked(payload["jti"]) is True

    def test_revoking_one_token_does_not_affect_a_different_token(self, clean_redis):
        token_a = create_access_token("alice", "analyst")
        token_b = create_access_token("alice", "analyst")
        payload_a = decode_access_token(token_a)
        payload_b = decode_access_token(token_b)

        revoke_token(payload_a["jti"], datetime.fromtimestamp(payload_a["exp"], tz=timezone.utc))

        assert is_revoked(payload_a["jti"]) is True
        assert is_revoked(payload_b["jti"]) is False

    def test_revocation_entry_expires_with_a_real_short_ttl(self, clean_redis):
        """Confirms the TTL mechanism actually works against real Redis
        — not asserting on implementation details, asserting on the
        actual observable behavior (key exists, then genuinely doesn't,
        after real wall-clock time passes)."""
        jti = "short-lived-test-jti"
        revoke_token(jti, datetime.now(timezone.utc) + timedelta(seconds=1))
        assert is_revoked(jti) is True
        time.sleep(1.5)
        assert is_revoked(jti) is False

    def test_is_revoked_fails_open_when_redis_unreachable(self):
        """A deliberately-broken client (wrong port) simulates Redis
        being down — is_revoked must return False (not raise), matching
        the documented fail-open trade-off."""
        broken_client = redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2, socket_timeout=0.2)
        assert is_revoked("any-jti", client=broken_client) is False
