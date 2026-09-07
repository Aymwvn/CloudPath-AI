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


class StatisticsOut(BaseModel):
    node_count: int
    edge_count: int
    node_types: dict[str, int]
    edge_types: dict[str, int]
    attack_path_count: int
    critical_path_count: int
