"""
Phase 9 — rehydration queries.

Rebuilds a fully-functional ScanRecord (including a live GraphEngine)
from persisted rows, so PostgresScanStore.get()/latest() are genuine
drop-in replacements for InMemoryScanStore — the FastAPI layer in
backend/main.py doesn't need to know or care which store produced the
ScanRecord it's reading.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.db import models
from backend.scan_service import ScanRecord
from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.graph.builder import GraphEngine
from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult
from engine.risk.engine import RiskAssessment


def rebuild_scan_record(session: Session, scan_id: str) -> ScanRecord | None:
    job = session.get(models.ScanJobModel, scan_id)
    if not job:
        return None

    scan_result = ScanResult(account_id=job.account_external_id, provider="aws")

    asset_rows = session.query(models.AssetModel).filter_by(scan_job_id=scan_id).all()
    for row in asset_rows:
        scan_result.assets.append(
            Asset(
                id=row.asset_id,
                type=NodeType(row.type),
                account_id=row.account_id,
                region=row.region,
                arn=row.arn,
                name=row.name,
                tags=row.tags or {},
                public=row.public,
                sensitivity=row.sensitivity,
                raw_metadata=row.raw_metadata or {},
                updated_at=row.updated_at,
            )
        )

    rel_rows = session.query(models.RelationshipModel).filter_by(scan_job_id=scan_id).all()
    for row in rel_rows:
        scan_result.relationships.append(
            Relationship(
                source_id=row.source_id,
                target_id=row.target_id,
                type=EdgeType(row.type),
                evidence=row.evidence or {},
                confidence=row.confidence,
            )
        )

    if job.error:
        scan_result.errors = job.error.split("; ")

    graph_engine = GraphEngine()
    graph_engine.build(scan_result)

    attack_paths: list[tuple[AttackPath, RiskAssessment]] = []
    path_rows = (
        session.query(models.AttackPathModel)
        .filter_by(scan_job_id=scan_id)
        .all()
    )
    for path_row in path_rows:
        step_rows = (
            session.query(models.AttackPathStepModel)
            .filter_by(attack_path_id=path_row.id)
            .order_by(models.AttackPathStepModel.step_order)
            .all()
        )
        steps = [
            AttackPathStep(
                source=s.source_id,
                target=s.target_id,
                edge_type=s.edge_type,
                evidence=s.evidence or {},
                confidence=s.confidence,
            )
            for s in step_rows
        ]
        attack_path = AttackPath(
            entry=path_row.entry_asset_id,
            target=path_row.target_asset_id,
            steps=steps,
            status=path_row.status,
        )
        risk = RiskAssessment(
            risk_score=path_row.risk_score,
            severity=path_row.severity,
            confidence=path_row.confidence,
            status=path_row.status,
            factor_breakdown={},  # not persisted at row level; recomputable via RiskEngine if needed
        )
        attack_paths.append((attack_path, risk))

    return ScanRecord(
        scan_id=job.id,
        scan_result=scan_result,
        graph_engine=graph_engine,
        attack_paths=attack_paths,
        status=job.status,
    )
