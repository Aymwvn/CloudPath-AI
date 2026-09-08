"""
Phase 12 — AI output schema.

Matches ARCHITECTURE.md Section 18 exactly. Every AI response is parsed
into this model before it's trusted anywhere else in the system — a
response that fails validation is discarded (see ai/explainer.py), never
silently shown as if it were valid.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class EvidenceItem(BaseModel):
    field: str
    value: str


class MitreTechnique(BaseModel):
    id: str
    name: str


class AttackPathAnalysis(BaseModel):
    summary: str
    classification: Literal["potential_attack_path", "confirmed_configuration_risk"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    entry_point: str
    target: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    attack_steps: list[str] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    impact: str
    missing_information: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    remediation_priority: Literal["critical", "high", "medium", "low"]


def validate_ai_output(raw: dict) -> AttackPathAnalysis:
    """Raises pydantic.ValidationError on anything that doesn't conform —
    callers (ai/explainer.py) are expected to catch this and retry/discard,
    never to pass an unvalidated dict further into the system."""
    return AttackPathAnalysis.model_validate(raw)


__all__ = ["AttackPathAnalysis", "EvidenceItem", "MitreTechnique", "validate_ai_output", "ValidationError"]
