"""
tests/cli_test_server.py — a minimal but REAL FastAPI app used only for
end-to-end CLI testing. This is NOT a mock: scan/asset/attack-path/
simulation/graph endpoints call the actual ScanService, GraphEngine,
AttackPathEngine, RiskEngine, and graph_export logic used everywhere
else in this project. Auth uses real JWT signing/verification (reusing
backend/auth.py) against an in-memory user dict instead of Postgres, so
CLI tests run fully offline and fast — this is a deliberate scope
reduction for TEST purposes only, not a suggestion that the real
backend should work this way.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError

from backend.auth import create_access_token, decode_access_token, hash_password, verify_password
from backend.graph_export import build_graph_payload
from backend.scan_service import ScanService

app = FastAPI(title="CloudPath AI (CLI test server)")
service = ScanService()

# username -> (bcrypt hash, role)
_USERS: dict[str, tuple[str, str]] = {
    "admin": (hash_password("admin-password"), "admin"),
    "analyst": (hash_password("analyst-password"), "analyst"),
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_access_token(token)
        return {"username": payload["sub"], "role": payload["role"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Not authenticated") from None


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
    user = _USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user[0]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(username=form_data.username, role=user[1])
    return {"access_token": token, "token_type": "bearer", "role": user[1]}


@app.post("/api/v1/scans")
def create_scan(body: dict, user: dict = Depends(get_current_user)) -> dict:
    try:
        record = service.run_scan(region=body.get("region", "us-east-1"), crown_jewel_ids=body.get("crown_jewel_ids"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc
    return {
        "scan_id": record.scan_id,
        "account_id": record.scan_result.account_id,
        "status": record.status,
        "asset_count": len(record.scan_result.assets),
        "relationship_count": len(record.scan_result.relationships),
        "errors": record.scan_result.errors,
    }


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(get_current_user)) -> dict:
    record = service.store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": record.scan_id,
        "account_id": record.scan_result.account_id,
        "status": record.status,
        "asset_count": len(record.scan_result.assets),
        "relationship_count": len(record.scan_result.relationships),
        "errors": record.scan_result.errors,
    }


@app.get("/api/v1/assets")
def list_assets(scan_id: str | None = None, user: dict = Depends(get_current_user)) -> list[dict]:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    return [
        {"id": a.id, "type": a.type.value, "name": a.name, "public": a.public, "region": a.region}
        for a in record.scan_result.assets
    ]


@app.get("/api/v1/attack-paths")
def list_attack_paths(scan_id: str | None = None, user: dict = Depends(get_current_user)) -> list[dict]:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    return [
        {
            "id": f"path-{i:03d}",
            "entry": path.entry,
            "target": path.target,
            "status": risk.status,
            "risk_score": risk.risk_score,
            "severity": risk.severity,
            "confidence": risk.confidence,
            "hop_count": path.hop_count,
            "steps": [
                {"source": s.source, "target": s.target, "edge_type": s.edge_type, "confidence": s.confidence}
                for s in path.steps
            ],
        }
        for i, (path, risk) in enumerate(record.attack_paths, start=1)
    ]


@app.get("/api/v1/statistics")
def get_statistics(scan_id: str | None = None, user: dict = Depends(get_current_user)) -> dict:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    graph_stats = record.graph_engine.stats()
    critical_count = sum(1 for _, risk in record.attack_paths if risk.severity == "CRITICAL")
    return {
        "node_count": graph_stats["node_count"],
        "edge_count": graph_stats["edge_count"],
        "node_types": graph_stats["node_types"],
        "edge_types": graph_stats["edge_types"],
        "attack_path_count": len(record.attack_paths),
        "critical_path_count": critical_count,
    }


@app.get("/api/v1/graph")
def get_graph(scan_id: str | None = None, user: dict = Depends(get_current_user)) -> dict:
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    return build_graph_payload(record)


@app.post("/api/v1/simulation")
def run_simulation(body: dict, user: dict = Depends(get_current_user)) -> dict:
    from engine.attack_paths.whatif import EdgeRemoval, WhatIfSimulator
    from engine.graph.builder import GraphEngine
    from engine.risk.engine import RiskEngine

    scan_id = body.get("scan_id")
    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available to simulate against")

    removals = [
        EdgeRemoval(source_id=e["source_id"], target_id=e["target_id"], edge_type=e["edge_type"])
        for e in body.get("remove_edges", [])
    ]
    result = WhatIfSimulator().simulate(record.scan_result, removals)

    graph_before = GraphEngine().build(record.scan_result)
    risk_engine = RiskEngine()

    def _to_out(paths):
        return [
            {"entry": p.entry, "target": p.target, "hop_count": p.hop_count,
             "risk_score": risk_engine.score(p, graph_before).risk_score}
            for p in paths
        ]

    return {
        "paths_before_count": len(result.paths_before),
        "paths_after_count": len(result.paths_after),
        "paths_blocked_count": result.paths_blocked_count,
        "blocked_paths": _to_out(result.blocked_paths),
        "still_open_paths": _to_out(result.still_open_paths),
    }
