"""
Phase 7 — Risk Engine.

Scores AttackPath objects from Phase 6 (0-100, mapped to LOW/MEDIUM/HIGH/
CRITICAL bands). Risk and confidence are tracked as two SEPARATE numbers
per ARCHITECTURE.md Section 13 — a path can be CRITICAL risk with low
confidence ("Potential Path"), and the two must never be collapsed into
one score.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from engine.attack_paths.engine import AttackPath
from engine.models import NodeType

# Weights sum to 100 — see ARCHITECTURE.md Section 14. Tunable, documented,
# not hidden inside magic numbers scattered through the codebase.
WEIGHTS = {
    "internet_reachable": 25,
    "crown_jewel_target": 20,
    "privilege_escalation": 20,
    "cross_account": 10,
    "short_path": 10,
    "missing_controls": 10,
    "sensitive_data": 5,
}

ESCALATION_EDGE_TYPES = {"CAN_PASS_ROLE", "CAN_ASSUME"}


@dataclass
class RiskAssessment:
    risk_score: int
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float
    status: str  # "path" | "potential_path" (carried over from AttackPath)
    factor_breakdown: dict[str, float]


class RiskEngine:
    def __init__(self, weights: dict[str, int] | None = None, crown_jewel_ids: set[str] | None = None):
        self.weights = weights or WEIGHTS
        self.crown_jewel_ids = crown_jewel_ids or set()

    def score(self, path: AttackPath, graph: nx.DiGraph) -> RiskAssessment:
        factors = self._compute_factors(path, graph)
        # Each factor is a 0.0-1.0 fraction of its weight's maximum
        # contribution. Weights sum to 100, so multiplying factor * weight
        # directly (no extra /100) gives a natural 0-100 total.
        raw_score = sum(factors[key] * self.weights[key] for key in self.weights)
        risk_score = max(0, min(100, round(raw_score)))

        return RiskAssessment(
            risk_score=risk_score,
            severity=self._band(risk_score),
            confidence=round(path.average_confidence, 2),
            status=path.status,
            factor_breakdown=factors,
        )

    def _compute_factors(self, path: AttackPath, graph: nx.DiGraph) -> dict[str, float]:
        entry_data = graph.nodes.get(path.entry, {})
        target_data = graph.nodes.get(path.target, {})

        internet_reachable = 1.0 if (entry_data.get("type") == NodeType.INTERNET.value or entry_data.get("public")) else 0.0

        crown_jewel_target = 1.0 if path.target in self.crown_jewel_ids else (
            0.6 if target_data.get("type") in {NodeType.RDS.value, NodeType.SECRET.value, NodeType.KMS_KEY.value} else 0.3
        )

        has_escalation = any(step.edge_type in ESCALATION_EDGE_TYPES for step in path.steps)
        privilege_escalation = 1.0 if has_escalation else 0.0

        cross_account = 1.0 if any("account" in step.evidence.get("trust_statement", {}).__str__().lower() for step in path.steps if step.edge_type == "TRUSTS") else 0.0

        # shorter paths are riskier — normalize against a 10-hop ceiling
        short_path = max(0.0, 1.0 - (path.hop_count / 10))

        # crude proxy for "missing compensating controls": no condition keys
        # present on any escalation-relevant edge's evidence
        missing_controls = 1.0 if has_escalation and not any(
            "Condition" in str(step.evidence) for step in path.steps
        ) else 0.0

        sensitive_data = 1.0 if target_data.get("type") in {NodeType.S3.value, NodeType.RDS.value, NodeType.SECRET.value} else 0.0

        return {
            "internet_reachable": internet_reachable,
            "crown_jewel_target": crown_jewel_target,
            "privilege_escalation": privilege_escalation,
            "cross_account": cross_account,
            "short_path": short_path,
            "missing_controls": missing_controls,
            "sensitive_data": sensitive_data,
        }

    @staticmethod
    def _band(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"
