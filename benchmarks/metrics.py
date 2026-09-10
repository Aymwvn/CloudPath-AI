"""
Phase 17 — benchmark metrics.

Generic precision/recall/F1 calculators (used for asset discovery,
attack path discovery, and MITRE mapping accuracy — ARCHITECTURE.md
Section 33), plus a hallucination-rate checker for AI output that
doesn't require a real LLM call to be meaningful: it checks whether
every value the model claims as "evidence" is actually traceable to the
evidence it was given, which is exactly the property Section 16
("Evidence-First AI") requires regardless of which model produced it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass
class PrecisionRecallResult:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0  # no predictions, nothing wrong claimed

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0  # nothing to find, nothing missed

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def precision_recall(predicted: set[T], expected: set[T]) -> PrecisionRecallResult:
    """Set-based precision/recall — predicted and expected must be
    hashable representations of the same kind of thing (e.g. tuples of
    (entry, target, hop_count) for attack paths, or asset ids for
    discovery accuracy)."""
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    return PrecisionRecallResult(true_positives=tp, false_positives=fp, false_negatives=fn)


@dataclass
class TimingResult:
    label: str
    seconds: float


def time_it(label: str, fn: Callable[[], T]) -> tuple[T, TimingResult]:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return result, TimingResult(label=label, seconds=elapsed)


@dataclass
class HallucinationCheckResult:
    total_evidence_items: int
    unsupported_items: int

    @property
    def hallucination_rate(self) -> float:
        if self.total_evidence_items == 0:
            return 0.0
        return self.unsupported_items / self.total_evidence_items


def check_evidence_hallucination(
    ai_evidence: list[dict], source_evidence: list[dict]
) -> HallucinationCheckResult:
    """For each evidence item the AI claims, checks whether its `value`
    string appears anywhere in the source evidence it was actually given
    (ai/prompt.py's <UNTRUSTED_CLOUD_DATA> block). An item whose value
    can't be found anywhere in the source is flagged as unsupported —
    a proxy for "the model invented this detail rather than citing what
    it was shown." This is intentionally a substring check, not exact-
    match, since models commonly reformat values (e.g. quoting them)
    without inventing new information.
    """
    source_text = _flatten_to_text(source_evidence)
    unsupported = 0

    for item in ai_evidence:
        value = str(item.get("value", ""))
        if not value:
            continue
        if value not in source_text:
            unsupported += 1

    return HallucinationCheckResult(total_evidence_items=len(ai_evidence), unsupported_items=unsupported)


def _flatten_to_text(evidence_list: list[dict]) -> str:
    import json

    return json.dumps(evidence_list, default=str)
