"""
Phase 12 — AttackPathExplainer.

Ties together: prompt construction (ai/prompt.py) -> provider call
(ai/providers/*) -> JSON parse -> schema validation (ai/schema.py). On
invalid JSON or a schema-validation failure, retries once with an error
hint appended; if that also fails, returns None rather than surfacing
unvalidated data — matches ARCHITECTURE.md Section 18: "Validate all
model output."
"""
from __future__ import annotations

import json
import logging

from ai.prompt import SYSTEM_PROMPT, build_user_prompt
from ai.providers.base import LLMProvider
from ai.schema import AttackPathAnalysis, validate_ai_output
from engine.attack_paths.engine import AttackPath
from engine.risk.engine import RiskAssessment
from pydantic import ValidationError

logger = logging.getLogger(__name__)


class AttackPathExplainer:
    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def explain(self, path: AttackPath, risk: RiskAssessment) -> AttackPathAnalysis | None:
        user_prompt = build_user_prompt(path, risk)

        result = self._try_generate(SYSTEM_PROMPT, user_prompt)
        if result is not None:
            return result

        # one retry with an explicit correction hint — a single transient
        # bad-JSON response shouldn't discard a perfectly good attack path
        retry_prompt = (
            user_prompt
            + "\n\nYour previous response was not valid JSON matching the required schema. "
            "Respond with ONLY the JSON object, nothing else."
        )
        return self._try_generate(SYSTEM_PROMPT, retry_prompt)

    def _try_generate(self, system_prompt: str, user_prompt: str) -> AttackPathAnalysis | None:
        try:
            raw_text = self.provider.generate_json(system_prompt, user_prompt)
        except Exception as exc:  # noqa: BLE001 - provider/network failures shouldn't crash the scan
            logger.warning("LLM provider call failed: %s", exc)
            return None

        try:
            raw_dict = json.loads(_strip_markdown_fences(raw_text))
        except json.JSONDecodeError as exc:
            logger.warning("AI response was not valid JSON: %s", exc)
            return None

        try:
            return validate_ai_output(raw_dict)
        except ValidationError as exc:
            logger.warning("AI response failed schema validation: %s", exc)
            return None


def _strip_markdown_fences(text: str) -> str:
    """Some models wrap JSON in ```json ... ``` despite instructions not
    to — strip that defensively rather than failing validation on
    otherwise-correct output."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)
    return stripped
