"""
Shared pytest fixtures. Phase 18 requires JWT_SECRET_KEY to be set
before backend.auth is imported anywhere — set a fixed test key here so
every test file gets a consistent, working auth environment without
each one having to remember to set it.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only-never-use-in-production")

import pytest


@pytest.fixture
def analyst_token() -> str:
    from backend.auth import create_access_token

    return create_access_token(username="test-analyst", role="analyst")


@pytest.fixture
def viewer_token() -> str:
    from backend.auth import create_access_token

    return create_access_token(username="test-viewer", role="viewer")


@pytest.fixture
def admin_token() -> str:
    from backend.auth import create_access_token

    return create_access_token(username="test-admin", role="admin")


@pytest.fixture
def auth_headers(analyst_token: str) -> dict:
    """Default auth header for tests that don't care which role, as long
    as it's high enough to hit any endpoint (analyst covers everything
    except user management, which is admin-only)."""
    return {"Authorization": f"Bearer {analyst_token}"}
