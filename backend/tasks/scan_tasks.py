"""
Phase 10 — background scan task.

Moves scan execution off the request thread: `POST /api/v1/scans`
(updated in this phase) now creates a pending scan_job row and returns
scan_id immediately, then this Celery task does the actual work and
updates that row when done — matching ARCHITECTURE.md Section 30
("A scan should not block an HTTP request.").
"""
from __future__ import annotations

from backend.db.store import PostgresScanStore
from backend.scan_service import ScanService
from backend.tasks.celery_app import celery_app


def _default_store() -> PostgresScanStore:
    # imported lazily so tests can monkeypatch DATABASE_URL/session before
    # this is ever called
    from backend.db.session import SessionLocal

    return PostgresScanStore(session_factory=SessionLocal)


@celery_app.task(name="cloudpath.run_scan", bind=True, max_retries=1)
def run_scan_task(self, scan_id: str, region: str = "us-east-1", crown_jewel_ids: list[str] | None = None) -> str:
    store = _default_store()
    store.mark_running(scan_id)

    try:
        service = ScanService(store=store)
        record = service.run_scan(region=region, crown_jewel_ids=crown_jewel_ids, scan_id=scan_id)
        # ScanService.run_scan() already calls store.save(record) internally
        # (see backend/scan_service.py) — the pending row created by the API
        # before this task ran gets updated in place, not duplicated, since
        # PostgresScanStore.save() checks for an existing job with this id.
        return scan_id
    except Exception as exc:  # noqa: BLE001
        store.mark_failed(scan_id, str(exc))
        raise
