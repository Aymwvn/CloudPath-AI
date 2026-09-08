"""
Phase 3 — IAM analyzer.

Consumes the normalized Asset objects produced by AWSProvider (Phase 1/2)
and:
  1. Flags IAM findings (wildcard actions/resources, dangerous actions,
     cross-account trust) using the evaluation logic in policy_eval.py.
  2. Emits new Relationship objects (TRUSTS, CAN_ASSUME, CAN_PASS_ROLE)
     back into the graph — this is the bridge between "IAM finding" and
     "attack graph edge" described in ARCHITECTURE.md Section 13.

This module never talks to AWS directly — it only reads what's already
inside Asset.raw_metadata, keeping IAM analysis fully testable offline.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from engine.iam import policy_eval
from engine.models import Asset, EdgeType, NodeType, Relationship


@dataclass
class IAMFinding:
    asset_id: str
    category: str  # "wildcard_action" | "wildcard_resource" | "dangerous_action" | "cross_account_trust"
    severity: str  # "low" | "medium" | "high" | "critical"
    detail: str
    evidence: dict = field(default_factory=dict)


class IAMAnalyzer:
    def analyze(self, assets: list[Asset]) -> tuple[list[IAMFinding], list[Relationship]]:
        findings: list[IAMFinding] = []
        relationships: list[Relationship] = []

        roles_by_asset_id = {a.id: a for a in assets if a.type == NodeType.ROLE}

        for asset in roles_by_asset_id.values():
            findings.extend(self._analyze_policies(asset))
            relationships.extend(self._analyze_trust_policy(asset, roles_by_asset_id))
            relationships.extend(self._find_pass_role_edges(asset, roles_by_asset_id))

        return findings, relationships

    # ------------------------------------------------------------------
    def _iter_policy_documents(self, asset: Asset):
        policies = asset.raw_metadata.get("policies", {})
        for pol in policies.get("attached", []):
            yield pol["name"], pol["document"]
        for pol in policies.get("inline", []):
            yield pol["name"], pol["document"]

    def _analyze_policies(self, asset: Asset) -> list[IAMFinding]:
        findings: list[IAMFinding] = []
        for policy_name, document in self._iter_policy_documents(asset):
            for statement in policy_eval.parse_statements(document):
                if statement.effect.value != "Allow":
                    continue

                if policy_eval.is_wildcard_action(statement) and policy_eval.is_wildcard_resource(statement):
                    findings.append(
                        IAMFinding(
                            asset_id=asset.id,
                            category="wildcard_action_and_resource",
                            severity="critical",
                            detail=f"Policy '{policy_name}' grants '*' on '*' — effectively administrator access.",
                            evidence={"policy": policy_name},
                        )
                    )
                elif policy_eval.is_wildcard_action(statement):
                    findings.append(
                        IAMFinding(
                            asset_id=asset.id,
                            category="wildcard_action",
                            severity="high",
                            detail=f"Policy '{policy_name}' grants all actions ('*') on a scoped resource.",
                            evidence={"policy": policy_name},
                        )
                    )

                dangerous = policy_eval.find_dangerous_actions(statement)
                for action in dangerous:
                    findings.append(
                        IAMFinding(
                            asset_id=asset.id,
                            category="dangerous_action",
                            severity="high",
                            detail=f"Policy '{policy_name}' grants dangerous action '{action}'.",
                            evidence={"policy": policy_name, "action": action},
                        )
                    )
        return findings

    def _analyze_trust_policy(self, asset: Asset, roles_by_id: dict[str, Asset]) -> list[Relationship]:
        """Build TRUSTS / CAN_ASSUME edges from a role's AssumeRolePolicyDocument."""
        rels: list[Relationship] = []
        trust_doc = asset.raw_metadata.get("assume_role_policy")
        if not trust_doc:
            return rels

        for statement in policy_eval.parse_statements(trust_doc):
            if statement.effect.value != "Allow":
                continue

            principal = statement.raw.get("Principal", {})
            aws_principals = principal.get("AWS") if isinstance(principal, dict) else None
            aws_principals = aws_principals if isinstance(aws_principals, list) else (
                [aws_principals] if aws_principals else []
            )

            for principal_arn in aws_principals:
                source_id = self._principal_to_asset_id(principal_arn, asset.account_id)
                # NOTE: only CAN_ASSUME is emitted here, not a separate
                # TRUSTS edge for the same (source, target) pair. The graph
                # engine (Phase 5) uses a plain DiGraph, which can only
                # hold one edge between a given node pair — a second edge
                # type added for the same pair silently overwrites the
                # first. CAN_ASSUME already conveys this trust relationship
                # for attack-path traversal purposes, so a duplicate TRUSTS
                # edge here would just collide with it and lose data. See
                # docs/PHASE13-16_NOTES.md for the full writeup — this was
                # caught by Phase 16's synthetic scenario tests.
                rels.append(
                    Relationship(
                        source_id=source_id,
                        target_id=asset.id,
                        type=EdgeType.CAN_ASSUME,
                        evidence={"trust_statement": statement.raw},
                        confidence=1.0 if source_id in roles_by_id or source_id.startswith("aws:account/") else 0.7,
                    )
                )

            service_principals = principal.get("Service") if isinstance(principal, dict) else None
            if service_principals:
                # service-linked trust (e.g. ec2.amazonaws.com, lambda.amazonaws.com)
                # recorded as evidence but not turned into a graph node.
                # No CAN_ASSUME collision risk here since service principals
                # never get a CAN_ASSUME edge (they're not assumable identities
                # in our graph), so TRUSTS is the only edge for this pair.
                rels.append(
                    Relationship(
                        source_id=f"aws:service/{service_principals if isinstance(service_principals, str) else service_principals[0]}",
                        target_id=asset.id,
                        type=EdgeType.TRUSTS,
                        evidence={"trust_statement": statement.raw},
                        confidence=0.6,
                    )
                )

        return rels

    def _find_pass_role_edges(self, asset: Asset, roles_by_id: dict[str, Asset]) -> list[Relationship]:
        """If this role/user can iam:PassRole, record a CAN_PASS_ROLE edge
        to every other role it's scoped to (or all roles, if unscoped)."""
        rels: list[Relationship] = []
        for _, document in self._iter_policy_documents(asset):
            for statement in policy_eval.parse_statements(document):
                if statement.effect.value != "Allow":
                    continue
                if not any(policy_eval._matches(a, "iam:passrole") for a in statement.actions):
                    continue

                targets = (
                    roles_by_id.values()
                    if policy_eval.is_wildcard_resource(statement)
                    else [r for r in roles_by_id.values() if r.arn in statement.resources]
                )
                for target in targets:
                    if target.id == asset.id:
                        continue
                    rels.append(
                        Relationship(
                            source_id=asset.id,
                            target_id=target.id,
                            type=EdgeType.CAN_PASS_ROLE,
                            evidence={"action": "iam:PassRole"},
                            confidence=0.9 if not policy_eval.is_wildcard_resource(statement) else 0.6,
                        )
                    )
        return rels

    @staticmethod
    def _principal_to_asset_id(principal_arn: str, account_id: str) -> str:
        if principal_arn == "*":
            return "aws:internet"
        if ":root" in principal_arn:
            return f"aws:account/{principal_arn.split(':')[4]}"
        if ":role/" in principal_arn:
            return f"aws:iam:role/{principal_arn.split('/')[-1]}"
        if ":user/" in principal_arn:
            return f"aws:iam:user/{principal_arn.split('/')[-1]}"
        return principal_arn
