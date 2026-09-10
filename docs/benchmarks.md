# CloudPath AI — Benchmark Results

Generated: 2026-09-09T10:57:22.953796+00:00
Python: 3.12.3 on Linux 6.18.44-fc-v24

Reproduce with `python -m benchmarks.run_benchmark`. No Postgres, Redis, or real LLM API key required — this exercises the pure engine layer plus a mock AI provider.

## Per-scenario accuracy

| Scenario | Path P/R/F1 | Finding P/R/F1 | MITRE P/R/F1 | Time (s) |
|---|---|---|---|---|
| public_ec2_to_s3 | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 0.4ms |
| pass_role_escalation | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 0.3ms |
| public_bucket | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 0.1ms |
| open_security_group | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 0.0ms |

## Aggregate (macro-average across scenarios)

- Attack path F1: **1.00**
- Finding detection F1: **1.00**
- MITRE mapping F1: **1.00**
- Total pipeline time across all scenarios: **0.9ms**

## AI hallucination check

Validates the hallucination-rate metric itself by running it against a clean (fully grounded) mock response and a deliberately fabricated one — the metric should read ~0% for the clean response and >0% for the fabricated one.

- Clean response hallucination rate: **0%** (0/1 unsupported)
- Fabricated response hallucination rate: **100%** (2/2 unsupported)

## Interpreting these numbers

- A scenario scoring below 1.0 F1 on findings/MITRE most often means the ground truth in `benchmarks/scenarios.py` expects a category the current ruleset doesn't cover yet, not that a real bug exists — check the specific mismatch before assuming either the code or the ground truth is right.
- These are SYNTHETIC scenarios (see `docs/PHASE16_NOTES.md` for which ones use real moto-mocked AWS calls vs. hand-built fixtures) — they measure whether the engines behave correctly on known inputs, not real-world false-positive/negative rates against production cloud accounts, which would need a much larger labeled dataset.
