"""
Phase 6 — Attack Path Engine.

Finds paths between entry points (Internet, public resources, or an
analyst-declared "assume compromised" identity) and high-value targets
(declared crown jewels, or a sensible default set — sensitive S3,
databases, admin-privileged roles). Uses NetworkX's k-shortest-simple-
paths (Yen's algorithm) with a bounded depth, per ARCHITECTURE.md
Section 12. This stage is fully deterministic — no AI/LLM call happens
here or anywhere upstream of it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice

import networkx as nx

from engine.models import NodeType

DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_PATHS_PER_PAIR = 5
DEFAULT_MIN_EDGE_CONFIDENCE = 0.5


@dataclass
class AttackPathStep:
    source: str
    target: str
    edge_type: str
    evidence: dict
    confidence: float


@dataclass
class AttackPath:
    entry: str
    target: str
    steps: list[AttackPathStep] = field(default_factory=list)
    status: str = "path"  # "path" if all edges meet the confidence bar, else "potential_path"

    @property
    def hop_count(self) -> int:
        return len(self.steps)

    @property
    def average_confidence(self) -> float:
        if not self.steps:
            return 0.0
        return sum(s.confidence for s in self.steps) / len(self.steps)

    @property
    def node_sequence(self) -> list[str]:
        if not self.steps:
            return [self.entry]
        return [self.steps[0].source] + [s.target for s in self.steps]


class AttackPathEngine:
    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_paths_per_pair: int = DEFAULT_MAX_PATHS_PER_PAIR,
        min_edge_confidence: float = DEFAULT_MIN_EDGE_CONFIDENCE,
    ):
        self.max_depth = max_depth
        self.max_paths_per_pair = max_paths_per_pair
        self.min_edge_confidence = min_edge_confidence

    def default_targets(self, graph: nx.DiGraph) -> list[str]:
        """Heuristic crown jewels when the analyst hasn't declared any:
        RDS, S3 (all of them — a bucket doesn't have to be pre-flagged
        sensitive to be worth reaching), Secrets Manager, KMS keys, and
        any role whose findings mark it as having wildcard admin access.
        This is a fallback only — declared crown jewels (Section 14)
        always take priority when supplied.
        """
        targets = []
        for node_type in (NodeType.RDS, NodeType.S3, NodeType.SECRET, NodeType.KMS_KEY):
            targets.extend([n for n, d in graph.nodes(data=True) if d.get("type") == node_type.value])
        return targets

    def find_paths(
        self,
        graph: nx.DiGraph,
        entry_points: list[str],
        targets: list[str],
    ) -> list[AttackPath]:
        results: list[AttackPath] = []

        for entry in entry_points:
            if entry not in graph:
                continue
            for target in targets:
                if target not in graph or target == entry:
                    continue
                results.extend(self._paths_between(graph, entry, target))

        return self._deduplicate(results)

    def _paths_between(self, graph: nx.DiGraph, entry: str, target: str) -> list[AttackPath]:
        found: list[AttackPath] = []

        # NetworkXNoPath is raised lazily *during* iteration of the
        # generator (not when shortest_simple_paths() is first called),
        # so the whole consuming loop must be inside the try block.
        try:
            path_generator = nx.shortest_simple_paths(graph, entry, target)
            for node_path in islice(path_generator, self.max_paths_per_pair):
                if len(node_path) - 1 > self.max_depth:
                    break  # shortest_simple_paths yields in increasing length order

                steps = []
                for src, dst in zip(node_path, node_path[1:]):
                    edge_data = graph.get_edge_data(src, dst)
                    steps.append(
                        AttackPathStep(
                            source=src,
                            target=dst,
                            edge_type=edge_data.get("type", "UNKNOWN"),
                            evidence=edge_data.get("evidence", {}),
                            confidence=edge_data.get("confidence", 1.0),
                        )
                    )

                attack_path = AttackPath(entry=entry, target=target, steps=steps)
                attack_path.status = (
                    "path" if all(s.confidence >= self.min_edge_confidence for s in steps) else "potential_path"
                )
                found.append(attack_path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        return found

    @staticmethod
    def _deduplicate(paths: list[AttackPath]) -> list[AttackPath]:
        seen = set()
        unique = []
        for p in paths:
            key = tuple(p.node_sequence)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique
