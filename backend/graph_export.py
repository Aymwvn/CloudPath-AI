"""
Post-v1.0 — graph export for the interactive attack graph visualization.

Converts the internal NetworkX graph (engine/graph/builder.py) plus the
scored attack paths already computed by ScanService into a plain JSON
structure a frontend graph-rendering library (React Flow) can consume
directly, with no further graph logic needed client-side.

Design choice: nodes/edges that participate in a discovered attack path
are annotated with that path's severity (max across all paths touching
them) so the frontend can color-code the graph without recomputing
anything — the backend is the single source of truth for what's
"dangerous," matching the platform's core rule that risk determination
never happens on the client.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from backend.scan_service import ScanRecord

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class GraphNodeOut:
    id: str
    type: str
    label: str
    public: bool
    max_severity: str | None  # highest severity of any attack path touching this node, if any
    on_attack_path: bool

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "public": self.public,
            "max_severity": self.max_severity,
            "on_attack_path": self.on_attack_path,
        }


@dataclass
class GraphEdgeOut:
    id: str
    source: str
    target: str
    type: str
    confidence: float
    max_severity: str | None
    on_attack_path: bool

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "confidence": self.confidence,
            "max_severity": self.max_severity,
            "on_attack_path": self.on_attack_path,
        }


def _max_severity(current: str | None, candidate: str) -> str:
    if current is None:
        return candidate
    return candidate if SEVERITY_RANK.get(candidate, -1) > SEVERITY_RANK.get(current, -1) else current


def build_graph_payload(record: ScanRecord) -> dict:
    """Builds the full graph payload for a scan: every node/edge in the
    graph (not just ones on a discovered path — an analyst needs to see
    the whole environment, not just the dangerous parts), with attack-
    path membership and severity annotated wherever it applies.
    """
    graph: nx.DiGraph = record.graph_engine.graph

    node_severity: dict[str, str] = {}
    edge_severity: dict[tuple[str, str], str] = {}

    for path, risk in record.attack_paths:
        for step in path.steps:
            node_severity[step.source] = _max_severity(node_severity.get(step.source), risk.severity)
            node_severity[step.target] = _max_severity(node_severity.get(step.target), risk.severity)
            edge_key = (step.source, step.target)
            edge_severity[edge_key] = _max_severity(edge_severity.get(edge_key), risk.severity)

    nodes: list[dict] = []
    for node_id, data in graph.nodes(data=True):
        nodes.append(
            GraphNodeOut(
                id=node_id,
                type=data.get("type", "UNKNOWN"),
                label=data.get("name", node_id),
                public=bool(data.get("public", False)),
                max_severity=node_severity.get(node_id),
                on_attack_path=node_id in node_severity,
            ).to_dict()
        )

    edges: list[dict] = []
    for source, target, data in graph.edges(data=True):
        edge_key = (source, target)
        edges.append(
            GraphEdgeOut(
                id=f"{source}->{target}->{data.get('type', 'UNKNOWN')}",
                source=source,
                target=target,
                type=data.get("type", "UNKNOWN"),
                confidence=data.get("confidence", 1.0),
                max_severity=edge_severity.get(edge_key),
                on_attack_path=edge_key in edge_severity,
            ).to_dict()
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "attack_path_count": len(record.attack_paths),
            "nodes_on_attack_paths": len(node_severity),
        },
    }
