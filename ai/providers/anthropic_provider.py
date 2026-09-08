"""
Phase 12 — Anthropic provider.

Uses the official `anthropic` SDK. Requires ANTHROPIC_API_KEY in the
environment (never hardcoded, never logged — see ARCHITECTURE.md
Section 31's "no plaintext secrets" rule).
"""
from __future__ import annotations

import os

from ai.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str | None = None, max_tokens: int = 2000):
        self._model = model
        self._max_tokens = max_tokens
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY not set and no api_key provided")
        self._client = None  # lazy import/init — keeps this module importable without the SDK installed

    def _get_client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        client = self._get_client()
        response = client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")

    @property
    def model_name(self) -> str:
        return f"anthropic:{self._model}"
