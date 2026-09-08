"""
Phase 9 — PostgreSQL-backed scan store.

Same interface as `backend.scan_service.InMemoryScanStore` (save/get/
latest) so `ScanService` doesn't need to know which one it's using.
This is the real persistence layer described in ARCHITECTURE.md Section
16 — `InMemoryScanStore` from Phase 8 becomes the "fast local demo"
option, this becomes the default in docker-compose. get()/latest() fully
rehydrate a ScanRecord (via queries.rebuild_scan_record) so this is a
genuine drop-in replacement, not a partial stub.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from backend.db import models
from backend.db.queries import rebuild_scan_record
from backend.scan_service import ScanRecord


@dataclass
class PostgresScanStore:
    session_factory: callable  # () -> Session, e.g. backend.db.session.get_session

    def create_pending_job(self, scan_id: str, account_hint: str = "") -> None:
        """Phase 10: called synchronously by the API right when a scan is
        requested, so GET /scans/{id} can immediately return status
        'pending'/'running' while the Celery task does the real work."""
        session: Session = self.session_factory()
        try:
            session.add(
                models.ScanJobModel(id=scan_id, account_external_id=account_hint or "unknown", status="pending")
            )
            session.commit()
        finally:
            session.close()

    def mark_running(self, scan_id: str) -> None:
        self._update_status(scan_id, "running")

    def mark_failed(self, scan_id: str, error: str) -> None:
        session: Session = self.session_factory()
        try:
            job = session.get(models.ScanJobModel, scan_id)
            if job:
                job.status = "failed"
                job.error = error
                session.commit()
        finally:
            session.close()

    def _update_status(self, scan_id: str, status: str) -> None:
        session: Session = self.session_factory()
        try:
            job = session.get(models.ScanJobModel, scan_id)
            if job:
                job.status = status
                session.commit()
        finally:
            session.close()

    def save(self, record: ScanRecord) -> None:
        session: Session = self.session_factory()
        try:
            existing_job = session.get(models.ScanJobModel, record.scan_id)
            if existing_job:
                # Phase 10: a pending job row was created before the async
                # task ran (see backend/tasks/scan_tasks.py) — update it in
                # place rather than inserting a duplicate.
                job = existing_job
                job.status = record.status
                job.asset_count = len(record.scan_result.assets)
                job.relationship_count = len(record.scan_result.relationships)
                job.error = "; ".join(record.scan_result.errors) or None
                job.account_external_id = record.scan_result.account_id
            else:
                job = models.ScanJobModel(
                    id=record.scan_id,
                    account_external_id=record.scan_result.account_id,
                    status=record.status,
                    asset_count=len(record.scan_result.assets),
                    relationship_count=len(record.scan_result.relationships),
                    error="; ".join(record.scan_result.errors) or None,
                )
                session.add(job)
                session.flush()

            for asset in record.scan_result.assets:
                session.add(
                    models.AssetModel(
                        asset_id=asset.id,
                        scan_job_id=job.id,
                        type=asset.type.value,
                        account_id=asset.account_id,
                        region=asset.region,
                        arn=asset.arn,
                        name=asset.name,
                        tags=asset.tags,
                        public=asset.public,
                        sensitivity=asset.sensitivity,
                        raw_metadata=_json_safe(asset.raw_metadata),
                    )
                )

            for rel in record.scan_result.relationships:
                session.add(
                    models.RelationshipModel(
                        scan_job_id=job.id,
                        source_id=rel.source_id,
                        target_id=rel.target_id,
                        type=rel.type.value,
                        evidence=_json_safe(rel.evidence),
                        confidence=rel.confidence,
                    )
                )

            for path, risk in record.attack_paths:
                path_row = models.AttackPathModel(
                    scan_job_id=job.id,
                    entry_asset_id=path.entry,
                    target_asset_id=path.target,
                    risk_score=risk.risk_score,
                    severity=risk.severity,
                    confidence=risk.confidence,
                    status=risk.status,
                )
                session.add(path_row)
                session.flush()  # populate path_row.id for the steps below

                for order, step in enumerate(path.steps):
                    session.add(
                        models.AttackPathStepModel(
                            attack_path_id=path_row.id,
                            step_order=order,
                            source_id=step.source,
                            target_id=step.target,
                            edge_type=step.edge_type,
                            confidence=step.confidence,
                            evidence=_json_safe(step.evidence),
                        )
                    )

            session.commit()
        finally:
            session.close()

    def get(self, scan_id: str) -> ScanRecord | None:
        session: Session = self.session_factory()
        try:
            return rebuild_scan_record(session, scan_id)
        finally:
            session.close()

    def latest(self) -> ScanRecord | None:
        session: Session = self.session_factory()
        try:
            job = (
                session.query(models.ScanJobModel)
                .order_by(models.ScanJobModel.started_at.desc())
                .first()
            )
            if not job:
                return None
            return rebuild_scan_record(session, job.id)
        finally:
            session.close()


def _json_safe(value: dict) -> dict:
    """SQLAlchemy's JSON column needs JSON-serializable values; our
    evidence dicts sometimes contain plain dict/list/str/number/bool/None
    already, but this guards against anything unexpected (e.g. datetime)
    slipping through from AWS raw responses."""
    import json

    return json.loads(json.dumps(value, default=str))
