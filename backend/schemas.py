"""
Phase 8 — API response schemas.

These are read/response models only for now (MVP is scan-triggered,
not persisted-and-queried against a real DB yet — that's Phase 9).
"""
from __future__ import annotations

from pydantic import BaseModel


class ScanRequest(BaseModel):
    region: str = "us-east-1"
    crown_jewel_ids: list[str] = []


class ScanSummary(BaseModel):
    scan_id: str
    account_id: str
    status: str
    asset_count: int
    relationship_count: int
    errors: list[str] = []


class AssetOut(BaseModel):
    id: str
    type: str
    name: str
    public: bool
    region: str | None = None


class AttackPathStepOut(BaseModel):
    source: str
    target: str
    edge_type: str
    confidence: float


class AttackPathOut(BaseModel):
    id: str
    entry: str
    target: str
    status: str
    risk_score: int
    severity: str
    confidence: float
    hop_count: int
    steps: list[AttackPathStepOut]


class AttackPathAnalysisOut(BaseModel):
    summary: str
    classification: str
    risk_score: int
    confidence: float
    entry_point: str
    target: str
    evidence: list[dict]
    attack_steps: list[str]
    mitre_techniques: list[dict]
    impact: str
    missing_information: list[str]
    recommended_actions: list[str]
    remediation_priority: str
    model_used: str | None = None


class EdgeRemovalIn(BaseModel):
    source_id: str
    target_id: str
    edge_type: str


class SimulationRequest(BaseModel):
    scan_id: str | None = None  # defaults to the latest in-memory scan if omitted
    remove_edges: list[EdgeRemovalIn]


class SimulationPathOut(BaseModel):
    entry: str
    target: str
    hop_count: int
    risk_score: int


class SimulationResultOut(BaseModel):
    paths_before_count: int
    paths_after_count: int
    paths_blocked_count: int
    blocked_paths: list[SimulationPathOut]
    still_open_paths: list[SimulationPathOut]


class StatisticsOut(BaseModel):
    node_count: int
    edge_count: int
    node_types: dict[str, int]
    edge_types: dict[str, int]
    attack_path_count: int
    critical_path_count: int
