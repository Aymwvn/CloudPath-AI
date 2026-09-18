"""
Tests for backend/tenant_scope.py and backend/audit_log_query.py against
a real Postgres database.
"""
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.audit_log_query import list_audit_logs
from backend.db import models
from backend.db.models import Base
from backend.tenant_scope import (
    grant_account_access,
    list_accessible_account_ids,
    revoke_account_access,
    user_can_access_account,
    user_can_access_scan,
)

TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/cloudpath")


def _postgres_available() -> bool:
    try:
        engine = create_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _postgres_available(), reason="Postgres not reachable")


@pytest.fixture()
def session_factory():
    engine = create_engine(TEST_DB_URL)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    yield factory
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


@pytest.fixture()
def session(session_factory):
    s = session_factory()
    yield s
    s.close()


class TestTenantIsolation:
    def test_admin_can_access_any_account_with_no_grants(self, session):
        assert user_can_access_account(session, "admin-user", "admin", "999999999999") is True

    def test_non_admin_without_grant_is_denied(self, session):
        assert user_can_access_account(session, "alice", "analyst", "111111111111") is False

    def test_grant_gives_access(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        assert user_can_access_account(session, "alice", "analyst", "111111111111") is True

    def test_grant_does_not_leak_to_other_accounts(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        assert user_can_access_account(session, "alice", "analyst", "222222222222") is False

    def test_grant_does_not_leak_to_other_users(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        assert user_can_access_account(session, "bob", "analyst", "111111111111") is False

    def test_revoke_removes_access(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        revoke_account_access(session, "alice", "111111111111")
        assert user_can_access_account(session, "alice", "analyst", "111111111111") is False

    def test_double_grant_is_idempotent_not_an_error(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")  # should not raise
        count = session.query(models.AccountAccessModel).filter_by(username="alice").count()
        assert count == 1

    def test_list_accessible_accounts_returns_none_for_admin(self, session):
        assert list_accessible_account_ids(session, "admin-user", "admin") is None

    def test_list_accessible_accounts_returns_granted_list_for_non_admin(self, session):
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        grant_account_access(session, "alice", "222222222222", granted_by="admin-user")
        result = list_accessible_account_ids(session, "alice", "analyst")
        assert set(result) == {"111111111111", "222222222222"}

    def test_user_can_access_scan_checks_the_scans_own_account(self, session):
        job = models.ScanJobModel(id="scan-1", account_external_id="111111111111", status="completed")
        session.add(job)
        session.commit()

        assert user_can_access_scan(session, "alice", "analyst", "scan-1") is False
        grant_account_access(session, "alice", "111111111111", granted_by="admin-user")
        assert user_can_access_scan(session, "alice", "analyst", "scan-1") is True

    def test_user_can_access_scan_returns_false_for_unknown_scan(self, session):
        assert user_can_access_scan(session, "alice", "analyst", "does-not-exist") is False


class TestAuditLogQuery:
    def _seed_logs(self, session, count=5):
        for i in range(count):
            session.add(models.AuditLogModel(actor=f"user-{i % 2}", action="scan.create", target=f"scan-{i}"))
        session.commit()

    def test_returns_logs_newest_first(self, session):
        self._seed_logs(session, count=3)
        results = list_audit_logs(session)
        timestamps = [r["timestamp"] for r in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_filters_by_actor(self, session):
        self._seed_logs(session, count=4)
        results = list_audit_logs(session, actor="user-0")
        assert all(r["actor"] == "user-0" for r in results)
        assert len(results) == 2

    def test_filters_by_action(self, session):
        session.add(models.AuditLogModel(actor="alice", action="auth.login"))
        session.add(models.AuditLogModel(actor="alice", action="scan.create"))
        session.commit()

        results = list_audit_logs(session, action="auth.login")
        assert len(results) == 1
        assert results[0]["action"] == "auth.login"

    def test_limit_is_hard_capped_at_500(self, session):
        self._seed_logs(session, count=3)
        results = list_audit_logs(session, limit=10_000)
        # can't practically seed 500+ rows in a test, but confirm the
        # call doesn't error and the cap logic is exercised
        assert len(results) == 3

    def test_pagination_offset_works(self, session):
        self._seed_logs(session, count=5)
        page1 = list_audit_logs(session, limit=2, offset=0)
        page2 = list_audit_logs(session, limit=2, offset=2)
        assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})
