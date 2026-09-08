"""
Phase 12 — mock provider.

Used by tests (and available for local dev without any API key) so the
whole AI layer — prompt construction, injection-defense wrapping, schema
validation, retry-on-invalid — is fully testable offline. Never used in
production; `ScanService`/API wiring should default to a real provider.
"""
from __future__ import annotations

from ai.providers.base import LLMProvider


class MockProvider(LLMProvider):
    def __init__(self, canned_response: str | None = None):
        self.canned_response = canned_response
        self.last_system_prompt: str | None = None
        self.last_user_prompt: str | None = None
        self.call_count = 0

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        if self.canned_response is not None:
            return self.canned_response
        return (
            '{"summary": "Mock analysis", "classification": "potential_attack_path", '
            '"risk_score": 50, "confidence": 0.8, "entry_point": "mock-entry", '
            '"target": "mock-target", "evidence": [], "attack_steps": [], '
            '"mitre_techniques": [], "impact": "Mock impact.", '
            '"missing_information": [], "recommended_actions": [], '
            '"remediation_priority": "medium"}'
        )

    @property
    def model_name(self) -> str:
        return "mock:test-model"
