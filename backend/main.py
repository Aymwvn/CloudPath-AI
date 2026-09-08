"""
Phase 8 — FastAPI backend (MVP subset of ARCHITECTURE.md Section 27).
Phase 10 adds an async scan path backed by Celery + Postgres alongside
the original synchronous/in-memory one (kept for local demo use and to
avoid breaking anything the Phase 8 test suite already depends on).

Auth/RBAC (Section 31) is still explicitly deferred to a later
hardening phase.
"""
from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException

from backend.scan_service import ScanService
from backend.schemas import (
    AssetOut,
    AttackPathAnalysisOut,
    AttackPathOut,
    AttackPathStepOut,
    EdgeRemovalIn,
    ScanRequest,
    ScanSummary,
    SimulationPathOut,
    SimulationRequest,
    SimulationResultOut,
    StatisticsOut,
)

app = FastAPI(title="CloudPath AI", version="0.1.0-mvp")
service = ScanService()  # in-memory, synchronous — Phase 8 behavior, unchanged


def _postgres_store():
    """Lazily build a PostgresScanStore. Returns None if Postgres isn't
    reachable/configured, so environments without it (e.g. Phase 8's own
    test run) don't break — only the new async endpoints depend on this."""
    try:
        from backend.db.session import SessionLocal
        from backend.db.store import PostgresScanStore

        return PostgresScanStore(session_factory=SessionLocal)
    except Exception:  # noqa: BLE001
        return None


@app.post("/api/v1/scans", response_model=ScanSummary)
def create_scan(request: ScanRequest) -> ScanSummary:
    """Synchronous scan (Phase 8 behavior) — blocks until done, in-memory
    only. Kept for local/demo use. For real usage prefer
    POST /api/v1/scans/async (Phase 10)."""
    try:
        record = service.run_scan(region=request.region, crown_jewel_ids=request.crown_jewel_ids)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc

    return ScanSummary(
        scan_id=record.scan_id,
        account_id=record.scan_result.account_id,
        status=record.status,
        asset_count=len(record.scan_result.assets),
        relationship_count=len(record.scan_result.relationships),
        errors=record.scan_result.errors,
    )


@app.post("/api/v1/scans/async", response_model=ScanSummary, status_code=202)
def create_scan_async(request: ScanRequest) -> ScanSummary:
    """Phase 10 — returns immediately with status 'pending'; the real
    work happens in a Celery worker (backend/tasks/scan_tasks.py) and
    persists to Postgres. Poll GET /api/v1/scans/{scan_id} for status."""
    store = _postgres_store()
    if store is None:
        raise HTTPException(status_code=503, detail="Postgres not configured/reachable for async scans")

    from backend.tasks.scan_tasks import run_scan_task

    scan_id = str(uuid.uuid4())
    store.create_pending_job(scan_id)
    run_scan_task.delay(scan_id, request.region, request.crown_jewel_ids)

    return ScanSummary(
        scan_id=scan_id,
        account_id="",
        status="pending",
        asset_count=0,
        relationship_count=0,
        errors=[],
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str) -> ScanSummary:
    # check the in-memory (synchronous) store first, then fall back to
    # Postgres for scans kicked off via the async endpoint
    record = service.store.get(scan_id)
    if not record:
        pg = _postgres_store()
        if pg is not None:
            try:
                record = pg.get(scan_id)
            except Exception:  # noqa: BLE001 - Postgres down/unreachable at query time, not just construction
                record = None
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanSummary(
        scan_id=record.scan_id,
        account_id=record.scan_result.account_id,
        status=record.status,
        asset_count=len(record.scan_result.assets),
        relationship_count=len(record.scan_result.relationships),
        errors=record.scan_result.errors,
    )


@app.get("/api/v1/assets", response_model=list[AssetOut])
def list_assets(scan_id: str | None = None) -> list[AssetOut]:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    return [
        AssetOut(id=a.id, type=a.type.value, name=a.name, public=a.public, region=a.region)
        for a in record.scan_result.assets
    ]


@app.get("/api/v1/attack-paths", response_model=list[AttackPathOut])
def list_attack_paths(scan_id: str | None = None) -> list[AttackPathOut]:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")

    return [
        AttackPathOut(
            id=f"path-{i:03d}",
            entry=path.entry,
            target=path.target,
            status=risk.status,
            risk_score=risk.risk_score,
            severity=risk.severity,
            confidence=risk.confidence,
            hop_count=path.hop_count,
            steps=[
                AttackPathStepOut(source=s.source, target=s.target, edge_type=s.edge_type, confidence=s.confidence)
                for s in path.steps
            ],
        )
        for i, (path, risk) in enumerate(record.attack_paths, start=1)
    ]


@app.get("/api/v1/statistics", response_model=StatisticsOut)
def get_statistics(scan_id: str | None = None) -> StatisticsOut:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")

    graph_stats = record.graph_engine.stats()
    critical_count = sum(1 for _, risk in record.attack_paths if risk.severity == "CRITICAL")

    return StatisticsOut(
        node_count=graph_stats["node_count"],
        edge_count=graph_stats["edge_count"],
        node_types=graph_stats["node_types"],
        edge_types=graph_stats["edge_types"],
        attack_path_count=len(record.attack_paths),
        critical_path_count=critical_count,
    )


@app.get("/api/v1/attack-paths/{attack_path_id}/mitre")
def get_mitre_mappings(attack_path_id: str) -> list[dict]:
    """Phase 14 — deterministic MITRE ATT&CK mappings, computed at scan
    persist time (backend/db/store.py), not by the AI layer."""
    from backend.db import models
    from backend.db.session import SessionLocal

    session = SessionLocal()
    try:
        rows = session.query(models.MitreTechniqueModel).filter_by(attack_path_id=attack_path_id).all()
        return [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "evidence": r.evidence,
                "confidence": r.confidence,
            }
            for r in rows
        ]
    finally:
        session.close()


@app.post("/api/v1/simulation", response_model=SimulationResultOut)
def run_simulation(request: SimulationRequest) -> SimulationResultOut:
    """Phase 15 — what-if analysis. Removes the given edges from a copy
    of the graph and shows which attack paths get blocked. Pure
    simulation — never touches real cloud infrastructure."""
    from engine.attack_paths.whatif import EdgeRemoval, WhatIfSimulator

    record = service.store.get(request.scan_id) if request.scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available to simulate against")

    removals = [EdgeRemoval(source_id=e.source_id, target_id=e.target_id, edge_type=e.edge_type) for e in request.remove_edges]
    result = WhatIfSimulator().simulate(record.scan_result, removals)

    risk_engine_for_before = None
    from engine.risk.engine import RiskEngine
    from engine.graph.builder import GraphEngine

    graph_before = GraphEngine().build(record.scan_result)
    risk_engine_for_before = RiskEngine()

    def _to_out(paths, graph):
        return [
            SimulationPathOut(
                entry=p.entry,
                target=p.target,
                hop_count=p.hop_count,
                risk_score=risk_engine_for_before.score(p, graph).risk_score,
            )
            for p in paths
        ]

    return SimulationResultOut(
        paths_before_count=len(result.paths_before),
        paths_after_count=len(result.paths_after),
        paths_blocked_count=result.paths_blocked_count,
        blocked_paths=_to_out(result.blocked_paths, graph_before),
        still_open_paths=_to_out(result.still_open_paths, graph_before),
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# ----------------------------------------------------------------------
# Phase 13 — AI analysis endpoints.
#
# These operate on a REAL persisted attack_path_id from Postgres (i.e.
# a scan run via /api/v1/scans/async), not the ordinal "path-001" ids
# the in-memory list endpoint above uses — AIAnalysisModel needs a real
# foreign key to attach to. See docs/PHASE13-16_NOTES.md.
# ----------------------------------------------------------------------
@app.post("/api/v1/attack-paths/{attack_path_id}/analyze", response_model=AttackPathAnalysisOut)
def analyze_attack_path(attack_path_id: str) -> AttackPathAnalysisOut:
    from backend.ai_service import AIAnalysisService, AttackPathNotFoundError, NoProviderConfiguredError
    from backend.db import models
    from backend.db.session import SessionLocal

    session = SessionLocal()
    try:
        ai_service = AIAnalysisService(session=session)
        try:
            analysis = ai_service.analyze(attack_path_id)
        except AttackPathNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except NoProviderConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        row = session.query(models.AIAnalysisModel).filter_by(attack_path_id=attack_path_id).one()
        return AttackPathAnalysisOut(**analysis.model_dump(), model_used=row.model_used)
    finally:
        session.close()


@app.get("/api/v1/attack-paths/{attack_path_id}/analysis", response_model=AttackPathAnalysisOut)
def get_attack_path_analysis(attack_path_id: str) -> AttackPathAnalysisOut:
    from backend.ai_service import AIAnalysisService
    from backend.db import models
    from backend.db.session import SessionLocal

    session = SessionLocal()
    try:
        ai_service = AIAnalysisService(session=session)
        analysis = ai_service.get_existing(attack_path_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="No AI analysis exists yet for this attack path")
        row = session.query(models.AIAnalysisModel).filter_by(attack_path_id=attack_path_id).one()
        return AttackPathAnalysisOut(**analysis.model_dump(), model_used=row.model_used)
    finally:
        session.close()
