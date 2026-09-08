"""
Phase 13 — wires the AI abstraction layer (Phase 12) into the actual
scan pipeline via a persisted-attack-path lookup.

This only operates against Postgres-persisted attack paths (i.e. scans
run via the async endpoint, Phase 10) because AIAnalysisModel needs a
real attack_path_id foreign key to attach to — the in-memory/synchronous
scan path (Phase 8) has no stable path ids to hang an analysis off of.
This is a real, documented limitation (see docs/PHASE13-16_NOTES.md),
not an oversight.
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from ai.explainer import AttackPathExplainer
from ai.providers.base import LLMProvider
from ai.schema import AttackPathAnalysis
from backend.db import models
from engine.attack_paths.engine import AttackPath, AttackPathStep
from engine.risk.engine import RiskAssessment


class NoProviderConfiguredError(RuntimeError):
    pass


class AttackPathNotFoundError(RuntimeError):
    pass


def get_default_provider() -> LLMProvider:
    """Picks a provider based on what's configured in the environment.
    Tests override this function directly rather than setting real API
    keys — see tests/test_ai_service.py."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        from ai.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider()
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_BASE_URL"):
        from ai.providers.openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider()
    raise NoProviderConfiguredError(
        "No AI provider configured — set ANTHROPIC_API_KEY, OPENAI_API_KEY, "
        "or OPENAI_BASE_URL (for a local Ollama instance)."
    )


class AIAnalysisService:
    def __init__(self, session: Session, provider: LLMProvider | None = None):
        self.session = session
        self._provider = provider  # lazily resolved via get_default_provider() if None

    def analyze(self, attack_path_id: str) -> AttackPathAnalysis:
        path_row = self.session.get(models.AttackPathModel, attack_path_id)
        if not path_row:
            raise AttackPathNotFoundError(f"Attack path '{attack_path_id}' not found")

        provider = self._provider or get_default_provider()

        step_rows = (
            self.session.query(models.AttackPathStepModel)
            .filter_by(attack_path_id=attack_path_id)
            .order_by(models.AttackPathStepModel.step_order)
            .all()
        )
        path = AttackPath(
            entry=path_row.entry_asset_id,
            target=path_row.target_asset_id,
            status=path_row.status,
            id=path_row.id,
            steps=[
                AttackPathStep(
                    source=s.source_id,
                    target=s.target_id,
                    edge_type=s.edge_type,
                    evidence=s.evidence or {},
                    confidence=s.confidence,
                )
                for s in step_rows
            ],
        )
        risk = RiskAssessment(
            risk_score=path_row.risk_score,
            severity=path_row.severity,
            confidence=path_row.confidence,
            status=path_row.status,
            factor_breakdown={},
        )

        explainer = AttackPathExplainer(provider=provider)
        analysis = explainer.explain(path, risk)
        if analysis is None:
            raise RuntimeError("AI provider returned no valid analysis after retry")

        self._persist(attack_path_id, analysis, provider.model_name)
        return analysis

    def _persist(self, attack_path_id: str, analysis: AttackPathAnalysis, model_used: str) -> None:
        existing = (
            self.session.query(models.AIAnalysisModel)
            .filter_by(attack_path_id=attack_path_id)
            .one_or_none()
        )
        payload = analysis.model_dump()
        if existing:
            existing.summary_json = payload
            existing.model_used = model_used
        else:
            self.session.add(
                models.AIAnalysisModel(
                    attack_path_id=attack_path_id,
                    summary_json=payload,
                    model_used=model_used,
                )
            )
        self.session.commit()

    def get_existing(self, attack_path_id: str) -> AttackPathAnalysis | None:
        row = (
            self.session.query(models.AIAnalysisModel)
            .filter_by(attack_path_id=attack_path_id)
            .one_or_none()
        )
        if not row:
            return None
        return AttackPathAnalysis.model_validate(row.summary_json)
