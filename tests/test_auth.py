"""
Phase 18 tests — authentication, RBAC, audit logging, rate limiting.
Runs against real Postgres and real Redis (not mocked) since these are
exactly the components a security-hardening phase needs to prove work
against real infrastructure, not just in isolation.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only-never-use-in-production")

from backend.auth import create_access_token, hash_password, verify_password
from backend.db.models import Base
from backend.main import app

client = TestClient(app)

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/cloudpath"
)


def _postgres_available() -> bool:
    try:
        engine = create_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _redis_available() -> bool:
    try:
        import redis

        client = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
        client.ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _postgres_available(), reason="Postgres not reachable")


@pytest.fixture()
def session_factory(monkeypatch):
    engine = create_engine(TEST_DB_URL)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr("backend.db.session.SessionLocal", factory)
    monkeypatch.setattr("backend.auth.SessionLocal", factory)
    yield factory
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


def _create_user(session_factory, username: str, password: str, role: str):
    from backend.db import models

    session = session_factory()
    try:
        session.add(models.UserModel(username=username, hashed_password=hash_password(password), role=role))
        session.commit()
    finally:
        session.close()


class TestPasswordHashing:
    def test_hash_and_verify_round_trip(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed)

    def test_wrong_password_fails_verification(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert not verify_password("wrong-password", hashed)

    def test_same_password_produces_different_hashes(self):
        """bcrypt salts automatically — two hashes of the same password
        should never be identical."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2
        assert verify_password("same-password", h1)
        assert verify_password("same-password", h2)


class TestLogin:
    def test_login_with_correct_credentials_returns_token(self, session_factory):
        _create_user(session_factory, "alice", "correct-password", "analyst")
        resp = client.post("/api/v1/auth/login", data={"username": "alice", "password": "correct-password"})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["role"] == "analyst"

    def test_login_with_wrong_password_returns_401(self, session_factory):
        _create_user(session_factory, "alice", "correct-password", "analyst")
        resp = client.post("/api/v1/auth/login", data={"username": "alice", "password": "wrong-password"})
        assert resp.status_code == 401

    def test_login_with_unknown_username_returns_401(self, session_factory):
        resp = client.post("/api/v1/auth/login", data={"username": "nobody", "password": "whatever"})
        assert resp.status_code == 401

    def test_login_writes_audit_log_on_success(self, session_factory):
        from backend.db import models

        _create_user(session_factory, "alice", "correct-password", "analyst")
        client.post("/api/v1/auth/login", data={"username": "alice", "password": "correct-password"})

        session = session_factory()
        try:
            logs = session.query(models.AuditLogModel).filter_by(actor="alice", action="auth.login").all()
            assert len(logs) == 1
        finally:
            session.close()

    def test_login_writes_audit_log_on_failure(self, session_factory):
        from backend.db import models

        _create_user(session_factory, "alice", "correct-password", "analyst")
        client.post("/api/v1/auth/login", data={"username": "alice", "password": "wrong-password"})

        session = session_factory()
        try:
            logs = session.query(models.AuditLogModel).filter_by(actor="alice", action="auth.login_failed").all()
            assert len(logs) == 1
        finally:
            session.close()


class TestJWTValidation:
    def test_tampered_token_is_rejected(self):
        token = create_access_token("alice", "admin")
        tampered = token[:-5] + "aaaaa"  # corrupt the signature
        resp = client.get("/api/v1/assets", headers={"Authorization": f"Bearer {tampered}"})
        assert resp.status_code == 401

    def test_missing_token_is_rejected(self):
        resp = client.get("/api/v1/assets")
        assert resp.status_code == 401

    def test_malformed_bearer_header_is_rejected(self):
        resp = client.get("/api/v1/assets", headers={"Authorization": "NotBearer garbage"})
        assert resp.status_code == 401


class TestRBAC:
    def test_viewer_cannot_register_users(self):
        viewer_token = create_access_token("viewer-user", "viewer")
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "new-user", "password": "password123", "role": "viewer"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403

    def test_analyst_cannot_register_users(self):
        analyst_token = create_access_token("analyst-user", "analyst")
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "new-user", "password": "password123", "role": "viewer"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_register_users(self, session_factory):
        admin_token = create_access_token("admin-user", "admin")
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "brand-new-user", "password": "password123", "role": "viewer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "brand-new-user"

    def test_duplicate_username_registration_returns_409(self, session_factory):
        admin_token = create_access_token("admin-user", "admin")
        headers = {"Authorization": f"Bearer {admin_token}"}
        client.post("/api/v1/auth/register", json={"username": "dupe", "password": "password123", "role": "viewer"}, headers=headers)
        resp = client.post("/api/v1/auth/register", json={"username": "dupe", "password": "password123", "role": "viewer"}, headers=headers)
        assert resp.status_code == 409


@pytest.mark.skipif(not _redis_available(), reason="Redis not reachable")
class TestRateLimiting:
    def test_rate_limiter_blocks_after_limit_exceeded(self):
        from backend.rate_limit import RateLimiter, get_redis_client

        redis_client = get_redis_client()
        # clear any leftover state from a previous run for this key
        for key in redis_client.scan_iter("ratelimit:test-rate-limit-user:*"):
            redis_client.delete(key)

        limiter = RateLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            limiter.check("test-rate-limit-user")  # should not raise

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            limiter.check("test-rate-limit-user")
        assert exc_info.value.status_code == 429

    def test_different_users_have_independent_limits(self):
        from backend.rate_limit import RateLimiter, get_redis_client

        redis_client = get_redis_client()
        for key in redis_client.scan_iter("ratelimit:test-user-*"):
            redis_client.delete(key)

        limiter = RateLimiter(limit=1, window_seconds=60)
        limiter.check("test-user-a")  # uses up user A's limit

        limiter.check("test-user-b")  # should NOT raise — independent key
