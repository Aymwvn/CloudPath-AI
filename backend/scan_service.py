"""
Phase 8 — Scan orchestration service.

Wires phases 1-7 together end to end: AWS discovery -> normalization ->
IAM/network analysis -> graph assembly -> attack path search -> risk
scoring. Results are held in-memory keyed by scan_id — this is explicitly
a placeholder for the PostgreSQL persistence layer that lands in Phase 9;
nothing here should be mistaken for the real storage design in
ARCHITECTURE.md Section 16.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from engine.attack_paths.engine import AttackPath, AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.iam.analyzer import IAMAnalyzer
from engine.models import ScanResult
from engine.network.analyzer import NetworkAnalyzer
from engine.risk.engine import RiskAssessment, RiskEngine
from providers.aws import collectors
from providers.aws.provider import AWSProvider


@dataclass
class ScanRecord:
    scan_id: str
    scan_result: ScanResult
    graph_engine: GraphEngine
    attack_paths: list[tuple[AttackPath, RiskAssessment]] = field(default_factory=list)
    status: str = "completed"


class InMemoryScanStore:
    """Placeholder for Phase 9's PostgreSQL-backed store."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}

    def save(self, record: ScanRecord) -> None:
        self._scans[record.scan_id] = record

    def get(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def latest(self) -> ScanRecord | None:
        if not self._scans:
            return None
        return list(self._scans.values())[-1]


class ScanService:
    def __init__(self, store: InMemoryScanStore | None = None):
        self.store = store or InMemoryScanStore()

    def run_scan(self, region: str = "us-east-1", crown_jewel_ids: list[str] | None = None) -> ScanRecord:
        provider = AWSProvider(region=region)

        scan_result = provider.discover_assets()
        scan_result = provider.discover_relationships(scan_result)

        iam_findings, iam_rels = IAMAnalyzer().analyze(scan_result.assets)
        net_findings, net_rels = NetworkAnalyzer().analyze(scan_result.assets)
        scan_result.relationships.extend(iam_rels + net_rels)

        try:
            profile_map = collectors.collect_instance_profiles(provider.session)
        except Exception:  # noqa: BLE001 - partial-scan tolerance, matches Phase 1 pattern
            profile_map = {}

        graph_engine = GraphEngine()
        graph = graph_engine.build(scan_result, instance_profile_to_role=profile_map)

        path_engine = AttackPathEngine()
        entry_points = graph_engine.entry_nodes()
        targets = crown_jewel_ids or path_engine.default_targets(graph)
        raw_paths = path_engine.find_paths(graph, entry_points, targets)

        risk_engine = RiskEngine(crown_jewel_ids=set(crown_jewel_ids or []))
        scored_paths = [(p, risk_engine.score(p, graph)) for p in raw_paths]
        scored_paths.sort(key=lambda pair: pair[1].risk_score, reverse=True)

        record = ScanRecord(
            scan_id=str(uuid.uuid4()),
            scan_result=scan_result,
            graph_engine=graph_engine,
            attack_paths=scored_paths,
        )
        self.store.save(record)
        return record
