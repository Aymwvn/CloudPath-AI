"""
Phase 9 — database session management.

DATABASE_URL defaults to a local Postgres instance matching
docker-compose.yml's `postgres` service. Tests override this with an
in-memory SQLite URL for speed (see tests/conftest.py) — the ORM layer
in models.py deliberately avoids Postgres-only column types so both
dialects work identically for our schema.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5432/cloudpath"
)

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_session() -> Session:
    return SessionLocal()
