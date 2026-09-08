"""
Phase 10 — Celery app configuration.

Broker/backend default to the local Redis instance matching
docker-compose.yml's `redis` service. `task_always_eager` is left False
here (real async behavior) — tests override it via `CELERY_TASK_ALWAYS_EAGER=1`
so they can run without a live worker process (see tests/test_scan_task.py).
"""
from __future__ import annotations

import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("cloudpath", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_always_eager=os.environ.get("CELERY_TASK_ALWAYS_EAGER", "0") == "1",
    task_eager_propagates=True,
)
