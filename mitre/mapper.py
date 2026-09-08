"""
Phase 14 — MITRE ATT&CK mapping.

Deterministic, evidence-bound mapping from graph edge types (not AI
guesswork) to MITRE ATT&CK techniques — per ARCHITECTURE.md Section 19:
"Only map techniques when evidence supports the mapping." Each mapping
below is anchored to a specific edge_type that can only appear in the
graph because a real, evidenced relationship was discovered by the
deterministic engines (Phases 1-7) — never inferred from AI output.
"""
from __future__ import annotations

from dataclasses import dataclass

from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.models import NodeType


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    evidence: dict
    confidence: float


# Each rule: (edge_type it fires on, resulting technique). A single step
# can match more than one rule (e.g. an EXPOSED_TO edge into a public
# EC2 instance is both "external remote services" and "exploit public-
# facing application" depending on context) — we keep the mapping list
# per rule simple and let a step contribute multiple techniques if more
# than one rule matches, rather than trying to pick "the one true"
# mapping, since the evidence genuinely supports more than one framing.
EDGE_TYPE_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "EXPOSED_TO": [
        ("T1190", "Exploit Public-Facing Application"),
        ("T1133", "External Remote Services"),
    ],
    "CAN_ASSUME": [
        ("T1078.004", "Valid Accounts: Cloud Accounts"),
    ],
    "TRUSTS": [
        ("T1078.004", "Valid Accounts: Cloud Accounts"),
    ],
    "CAN_PASS_ROLE": [
        ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    ],
}

# Target-node-type-specific techniques — these depend on what the LAST
# step in the path lands on, not the edge type itself.
TARGET_TYPE_TECHNIQUES: dict[NodeType, list[tuple[str, str]]] = {
    NodeType.S3: [("T1530", "Data from Cloud Storage")],
    NodeType.SECRET: [("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API")],
    NodeType.RDS: [("T1530", "Data from Cloud Storage")],  # closest documented technique for managed DB exfil
}


class MitreMapper:
    def map_path(self, path: AttackPath, target_node_type: NodeType | None = None) -> list[MitreMapping]:
        mappings: list[MitreMapping] = []
        seen_ids: set[str] = set()

        for step in path.steps:
            for technique_id, technique_name in EDGE_TYPE_TECHNIQUES.get(step.edge_type, []):
                mappings.append(self._build(technique_id, technique_name, step, seen_ids))

        if target_node_type and target_node_type in TARGET_TYPE_TECHNIQUES:
            last_step = path.steps[-1] if path.steps else None
            for technique_id, technique_name in TARGET_TYPE_TECHNIQUES[target_node_type]:
                mappings.append(
                    self._build(
                        technique_id,
                        technique_name,
                        last_step,
                        seen_ids,
                        fallback_evidence={"target": path.target, "target_type": target_node_type.value},
                    )
                )

        return [m for m in mappings if m is not None]

    def _build(
        self,
        technique_id: str,
        technique_name: str,
        step: AttackPathStep | None,
        seen_ids: set[str],
        fallback_evidence: dict | None = None,
    ) -> MitreMapping | None:
        # a technique already mapped once for this path isn't repeated —
        # the point is "does this path exhibit the technique", not a count
        if technique_id in seen_ids:
            return None
        seen_ids.add(technique_id)

        evidence = dict(step.evidence) if step else (fallback_evidence or {})
        confidence = step.confidence if step else 0.7

        return MitreMapping(
            technique_id=technique_id,
            technique_name=technique_name,
            evidence=evidence,
            confidence=confidence,
        )
