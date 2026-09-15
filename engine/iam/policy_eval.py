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
    # Reading a secret's plaintext value is a distinct, meaningful
    # capability worth flagging on its own — a role that can read
    # arbitrary secrets is a high-value target/pivot point even without
    # any privilege-escalation primitive alongside it.
    "secretsmanager:getsecretvalue",
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
