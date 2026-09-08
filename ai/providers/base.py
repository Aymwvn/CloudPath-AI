"""
Phase 12 — LLM provider abstraction.

Every backend (OpenAI-compatible, Anthropic-compatible, Ollama, a test
mock) implements this single method. Nothing above this layer (ai/
explainer.py, and eventually backend/main.py) needs to know which
concrete provider is in use — matches the CloudProvider pattern from
providers/base.py (Phase 1), applied to the AI layer instead of cloud
APIs.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """Return the model's raw text response. Callers are responsible
        for JSON-parsing and schema-validating it (ai/explainer.py) — this
        layer only knows how to talk to a specific vendor's API, nothing
        about our AttackPathAnalysis schema.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Identifier stored alongside AI output (AIAnalysisModel.model_used,
        Phase 9) so every explanation is traceable to what produced it."""
        raise NotImplementedError
