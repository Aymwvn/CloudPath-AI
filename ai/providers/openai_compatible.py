"""
Phase 12 — OpenAI-compatible provider.

Works against OpenAI itself, Ollama (via its `/v1/chat/completions`
OpenAI-compatibility endpoint — set base_url="http://localhost:11434/v1"
and api_key="ollama", any value works locally), or any other vendor that
speaks the same wire format. This is what makes "local models" (Section
15 of ARCHITECTURE.md) work without a separate Ollama-specific class.
"""
from __future__ import annotations

import os

from ai.providers.base import LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "not-needed-for-local-models")
        self._base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self._client = None

    def _get_client(self):
        if self._client is None:
            import openai

            self._client = openai.OpenAI(api_key=self._api_key, base_url=self._base_url)
        return self._client

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        client = self._get_client()
        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content or ""

    @property
    def model_name(self) -> str:
        prefix = "ollama" if self._base_url and "11434" in self._base_url else "openai"
        return f"{prefix}:{self._model}"
