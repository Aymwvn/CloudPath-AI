# Phase 17 — Benchmarking Notes

## What was built

`benchmarks/metrics.py` — generic, reusable precision/recall/F1
calculators plus an AI evidence-hallucination checker. `benchmarks/scenarios.py`
— 4 scenarios (a representative subset of Phase 16's 8) with explicit,
readable ground truth: exactly which attack paths, findings, and MITRE
techniques *should* be discovered. `benchmarks/run_benchmark.py` runs
every scenario through the full deterministic pipeline, times each
stage, computes precision/recall against ground truth, runs the
hallucination checker against both a clean and a deliberately-fabricated
mock AI response (to prove the checker itself discriminates correctly),
and writes `docs/benchmarks.md`.

**Run it yourself:**
```bash
python -m benchmarks.run_benchmark
```
No Postgres, Redis, or real LLM API key needed — pure engine layer +
`MockProvider`.

## Current results (see docs/benchmarks.md for the live, regeneratable version)

All 4 scenarios score 1.00 F1 on paths, findings, and MITRE mapping.
**This is expected, not something to be impressed by** — these are the
same scenario shapes the engines were designed and unit-tested against
in Phases 1-16, so a perfect score here mainly proves "the benchmark
harness correctly measures what the tests already established," not
"the engine is flawless in the wild." The hallucination checker
correctly reads 0% for a clean/grounded mock response and 100% for a
deliberately fabricated one — that's the number worth trusting, since it
validates the *checker*, not just the pipeline.

## Honest limitations (stated plainly, not glossed over)

1. **Benchmark scenarios can't currently score below 1.0 in any
   meaningful way** — since the ground truth in `scenarios.py` was
   written by hand-tracing what the current code actually does, a
   regression in the engine and a mistake in the ground truth would look
   identical (both show a mismatch). This benchmark is a **regression
   detector**, not an independent accuracy measurement — it will catch
   "this behavior changed," but "is this behavior actually correct cloud
   security analysis" still needs external validation (e.g. comparing
   against Prowler/ScoutSuite output on the same synthetic accounts, or
   manual security-analyst review), which isn't built yet.
2. **Only 4 of Phase 16's 8 scenarios are wired into the benchmark**,
   not all 8 — the other 4 (Lambda/RDS/cross-account/compromised-identity
   scenarios) need the same ground-truth-declaration treatment; skipped
   here to keep the first benchmarking pass reviewable rather than
   dumping all 8 at once. Same pattern, straightforward to extend.
3. **No historical tracking** — running the benchmark twice just
   overwrites `docs/benchmarks.md`; there's no `docs/benchmarks-history/`
   or trend line showing whether F1/timing is improving or regressing
   release over release. Worth adding once there's more than one commit
   of history to actually compare.
4. **AI hallucination checking is a substring match**, not semantic
   analysis — a model that paraphrases a true fact heavily enough could
   register as "unsupported" even though it isn't actually hallucinating,
   and conversely a model that hallucinates a value that happens to
   coincidentally match some unrelated source text would slip through.
   This is a real, known limitation of the technique, not hidden: it's a
   useful cheap proxy, not a rigorous guarantee.
5. **Timing numbers are meaningless for real capacity planning** — these
   scenarios have 1-5 assets each; ARCHITECTURE.md Section 30's actual
   performance target (500-resource account in under 5 minutes) needs a
   benchmark against a much larger synthetic account, which isn't built.

## Compatibility check

- Reuses the exact same scenario-building pattern as
  `tests/test_synthetic_scenarios.py` (Phase 16) — no new fixture style
  introduced.
- `benchmarks/metrics.py` has no dependency on anything AWS/Postgres/
  Celery-specific — it's pure math, testable and tested in isolation
  (`tests/test_benchmark_metrics.py`, 11 tests).
- All 92 tests pass (81 from phases 1-16 + 11 new metrics tests).
