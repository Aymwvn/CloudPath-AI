"""
Phase 3 — IAM policy evaluation logic.

This mirrors AWS's real evaluation order (see ARCHITECTURE.md Section 13):
  1. Explicit Deny always wins, anywhere it appears.
  2. Otherwise, an explicit Allow anywhere (identity policy, resource
     policy, or within the permission boundary) is required.
  3. Permission boundaries only ever narrow (they can never grant more
     than the identity policy would already allow).

This module is intentionally naive about resource ARNs matching (fnmatch-
style) because IAM's ARN wildcard semantics are well-defined; it does NOT
naively treat every "*" in the whole document as "critical" — see the
DEVELOPMENT RULE in ARCHITECTURE.md Section 8.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Effect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass
class Statement:
    effect: Effect
    actions: list[str]
    resources: list[str]
    conditions: dict[str, Any]
    raw: dict[str, Any]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_statements(policy_document: dict[str, Any]) -> list[Statement]:
    statements = _as_list(policy_document.get("Statement", []))
    parsed = []
    for stmt in statements:
        parsed.append(
            Statement(
                effect=Effect(stmt.get("Effect", "Deny")),
                actions=_as_list(stmt.get("Action", stmt.get("NotAction"))),
                resources=_as_list(stmt.get("Resource", stmt.get("NotResource"))),
                conditions=stmt.get("Condition", {}),
                raw=stmt,
            )
        )
    return parsed


def _matches(pattern: str, value: str) -> bool:
    """IAM action/resource matching is case-insensitive glob matching."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def statement_grants(statement: Statement, action: str, resource: str) -> bool:
    action_match = any(_matches(pat, action) for pat in statement.actions)
    resource_match = any(_matches(pat, resource) for pat in statement.resources) if statement.resources else True
    return action_match and resource_match


def evaluate(
    action: str,
    resource: str,
    identity_policies: list[dict[str, Any]],
    resource_policies: list[dict[str, Any]] | None = None,
    boundary_policy: dict[str, Any] | None = None,
) -> bool:
    """Return True if `action` on `resource` is effectively allowed.

    Order (mirrors AWS): explicit deny anywhere wins; otherwise an allow
    must exist in the identity/resource policy AND (if a boundary is set)
    within the boundary too.
    """
    all_identity_statements = [s for doc in identity_policies for s in parse_statements(doc)]
    all_resource_statements = [s for doc in (resource_policies or []) for s in parse_statements(doc)]

    combined = all_identity_statements + all_resource_statements

    if any(s.effect == Effect.DENY and statement_grants(s, action, resource) for s in combined):
        return False

    allowed = any(s.effect == Effect.ALLOW and statement_grants(s, action, resource) for s in combined)
    if not allowed:
        return False

    if boundary_policy:
        boundary_statements = parse_statements(boundary_policy)
        if any(s.effect == Effect.DENY and statement_grants(s, action, resource) for s in boundary_statements):
            return False
        boundary_allows = any(
            s.effect == Effect.ALLOW and statement_grants(s, action, resource) for s in boundary_statements
        )
        if not boundary_allows:
            return False

    return True


# Actions that are worth flagging as dangerous regardless of resource scope,
# because each one is a documented building block of a privilege-escalation
# or lateral-movement chain (see ARCHITECTURE.md Section 9).
DANGEROUS_ACTIONS = {
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:creataccesskey",
    "iam:createaccesskey",
    "iam:updateassumerolepolicy",
    "sts:assumerole",
    "lambda:updatefunctioncode",
    "lambda:createfunction",
}


def find_dangerous_actions(statement: Statement) -> list[str]:
    found = []
    for action in statement.actions:
        normalized = action.lower()
        if normalized == "*":
            found.append("*")
            continue
        for dangerous in DANGEROUS_ACTIONS:
            if _matches(action, dangerous):
                found.append(dangerous)
    return found


def is_wildcard_action(statement: Statement) -> bool:
    return any(a == "*" for a in statement.actions)


def is_wildcard_resource(statement: Statement) -> bool:
    return any(r == "*" for r in statement.resources)
