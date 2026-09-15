#!/bin/sh
# Runs pending Alembic migrations before starting the API — without
# this, a fresh `docker compose up` leaves the database schema-less and
# scripts/create_admin.py (or any API call) fails with "relation does
# not exist" on first run. This was a real gap: the original
# docker-compose.yml / README never actually ran migrations anywhere.
#
# Known limitation: if you ever scale the backend to multiple replicas,
# each replica running `alembic upgrade head` concurrently on startup
# is a race condition. Fine at this project's current single-replica
# scale; worth moving to a dedicated one-shot migration job/init
# container before scaling horizontally.
set -e

echo "[entrypoint] Running database migrations..."
alembic upgrade head

echo "[entrypoint] Starting API server..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
