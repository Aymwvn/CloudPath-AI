"""
Phase 8 — FastAPI backend (MVP subset of ARCHITECTURE.md Section 27).

Only the endpoints needed to exercise phases 1-7 end to end are
implemented here. Auth/RBAC (Section 31), PostgreSQL persistence
(Section 16), and background job workers (Section 30) are explicitly
deferred to later phases — this backend runs scans synchronously and
in-memory, which is fine for local/demo use but is NOT the final
architecture.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from backend.scan_service import ScanService
from backend.schemas import (
    AssetOut,
    AttackPathOut,
    AttackPathStepOut,
    ScanRequest,
    ScanSummary,
    StatisticsOut,
)

app = FastAPI(title="CloudPath AI", version="0.1.0-mvp")
service = ScanService()


@app.post("/api/v1/scans", response_model=ScanSummary)
def create_scan(request: ScanRequest) -> ScanSummary:
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


@app.get("/api/v1/scans/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str) -> ScanSummary:
    record = service.store.get(scan_id)
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
