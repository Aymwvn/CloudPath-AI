from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from engine.attack_paths.engine import AttackPath, AttackPathEngine
from engine.graph.builder import GraphEngine
from engine.models import ScanResult
from engine.risk.engine import RiskEngine


@dataclass
class EdgeRemoval:
    source_id: str
    target_id: str
    edge_type: str


@dataclass
class WhatIfResult:
    removed_edges: list[EdgeRemoval]
    paths_before: list[AttackPath]
    paths_after: list[AttackPath]
    blocked_paths: list[AttackPath] = field(default_factory=list)
    still_open_paths: list[AttackPath] = field(default_factory=list)
    new_risk_by_path_key: dict[tuple, int] = field(default_factory=dict)

    @property
    def paths_blocked_count(self) -> int:
        return len(self.blocked_paths)


class WhatIfSimulator:
    def __init__(self, path_engine: AttackPathEngine | None = None, risk_engine: RiskEngine | None = None):
        self.path_engine = path_engine or AttackPathEngine()
        self.risk_engine = risk_engine or RiskEngine()

    def simulate(self, scan: ScanResult, removals: list[EdgeRemoval],
                 entry_points: list[str] | None = None, targets: list[str] | None = None) -> WhatIfResult:
        graph_engine = GraphEngine()
        graph_before = graph_engine.build(scan)

        entries = entry_points or graph_engine.entry_nodes()
        target_nodes = targets or self.path_engine.default_targets(graph_before)

        paths_before = self.path_engine.find_paths(graph_before, entries, target_nodes)

        graph_after = self._apply_removals(graph_before, removals)
        paths_after = self.path_engine.find_paths(graph_after, entries, target_nodes)

        before_keys = {self._path_key(p) for p in paths_before}
        after_keys = {self._path_key(p) for p in paths_after}

        blocked = [p for p in paths_before if self._path_key(p) not in after_keys]
        still_open = [p for p in paths_after if self._path_key(p) in before_keys]

        new_risk = {self._path_key(p): self.risk_engine.score(p, graph_after).risk_score for p in paths_after}

        return WhatIfResult(removed_edges=removals, paths_before=paths_before, paths_after=paths_after,
                             blocked_paths=blocked, still_open_paths=still_open, new_risk_by_path_key=new_risk)

    @staticmethod
    def _apply_removals(graph: nx.DiGraph, removals: list[EdgeRemoval]) -> nx.DiGraph:
        new_graph = graph.copy()
        for removal in removals:
            if new_graph.has_edge(removal.source_id, removal.target_id):
                edge_data = new_graph.get_edge_data(removal.source_id, removal.target_id)
                if edge_data.get("type") == removal.edge_type:
                    new_graph.remove_edge(removal.source_id, removal.target_id)
        return new_graph

    @staticmethod
    def _path_key(path: AttackPath) -> tuple:
        return tuple(path.node_sequence)
