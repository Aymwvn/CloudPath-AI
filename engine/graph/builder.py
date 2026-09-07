"""
Phase 5 — Graph Engine.

Assembles persisted Asset/Relationship records into an in-memory NetworkX
DiGraph and exposes a clean traversal interface for the Attack Path Engine
(Phase 6). Per ARCHITECTURE.md Section 29, graph construction is kept
separate from graph traversal/ranking/persistence, so a later swap to
Neo4j only touches this module, not the Attack Path or Risk engines.
"""
from __future__ import annotations

import networkx as nx

from engine.models import Asset, EdgeType, NodeType, Relationship, ScanResult


class GraphEngine:
    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    # ------------------------------------------------------------------
    def build(self, scan: ScanResult, instance_profile_to_role: dict[str, str] | None = None) -> nx.DiGraph:
        """Build the graph from a ScanResult.

        `instance_profile_to_role` (Phase 1's collect_instance_profiles
        output) lets us resolve the approximate RUNS_AS edge recorded
        during AWS normalization into an exact role edge at full
        confidence — see docs/PHASE1-4_NOTES.md, Known Limitation #1.
        """
        self.graph = nx.DiGraph()

        for asset in scan.assets:
            self._add_asset(asset)

        resolved = self._resolve_instance_profile_edges(scan.relationships, instance_profile_to_role or {})

        for rel in resolved:
            self._add_relationship(rel)

        return self.graph

    def _add_asset(self, asset: Asset) -> None:
        self.graph.add_node(asset.id, asset=asset, type=asset.type.value, public=asset.public, name=asset.name)

    def _add_relationship(self, rel: Relationship) -> None:
        # Only add edges between nodes that actually exist in the graph —
        # an edge pointing at an asset we never discovered (e.g. a
        # cross-account role we don't have visibility into) is still
        # useful evidence, so add a lightweight placeholder node for it
        # rather than silently dropping the edge.
        for node_id in (rel.source_id, rel.target_id):
            if node_id not in self.graph:
                self.graph.add_node(node_id, asset=None, type="EXTERNAL", public=False, name=node_id)

        self.graph.add_edge(
            rel.source_id,
            rel.target_id,
            type=rel.type.value,
            evidence=rel.evidence,
            confidence=rel.confidence,
        )

    @staticmethod
    def _resolve_instance_profile_edges(
        relationships: list[Relationship], profile_to_role: dict[str, str]
    ) -> list[Relationship]:
        """Rewrite RUNS_AS edges pointing at an unresolved instance-profile
        placeholder id into an edge pointing at the real role, at full
        confidence, when we have the mapping."""
        resolved: list[Relationship] = []
        for rel in relationships:
            if rel.type == EdgeType.RUNS_AS and rel.target_id.startswith("aws:iam:instance-profile/"):
                profile_name = rel.target_id.split("/")[-1]
                role_name = profile_to_role.get(profile_name)
                if role_name:
                    resolved.append(
                        Relationship(
                            source_id=rel.source_id,
                            target_id=f"aws:iam:role/{role_name}",
                            type=EdgeType.RUNS_AS,
                            evidence={**rel.evidence, "resolved_via": "instance_profile_mapping"},
                            confidence=1.0,
                        )
                    )
                    continue
            resolved.append(rel)
        return resolved

    # ------------------------------------------------------------------
    # Query helpers used by the Attack Path Engine (Phase 6)
    # ------------------------------------------------------------------
    def entry_nodes(self) -> list[str]:
        """INTERNET plus anything flagged public."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") == NodeType.INTERNET.value or data.get("public"):
                nodes.append(node_id)
        return nodes

    def nodes_by_type(self, node_type: NodeType) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") == node_type.value]

    def stats(self) -> dict:
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "node_types": self._count_by(lambda d: d.get("type")),
            "edge_types": self._count_edge_types(),
        }

    def _count_by(self, key_fn) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            key = key_fn(data)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _count_edge_types(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            key = data.get("type")
            counts[key] = counts.get(key, 0) + 1
        return counts
