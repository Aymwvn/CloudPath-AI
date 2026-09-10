# Phase 16 — Synthetic Scenario Testing Notes

## What was built

`tests/test_synthetic_scenarios.py` — the 8 canonical scenarios from
ARCHITECTURE.md Section 32, each run through the **full deterministic
pipeline** (Graph Engine → Attack Path Engine → Risk Engine → MITRE
Mapper), with zero AI/LLM involvement anywhere — proving Section 3's
rule that the engine has to work correctly with AI fully disabled.

| # | Scenario | How it's built |
|---|---|---|
| 1 | Public EC2 → IAM role → S3 | Real moto-mocked AWS, real collectors |
| 2 | IAM user → AssumeRole → Admin role | Real `IAMAnalyzer`, hand-built assets |
| 3 | Public Lambda → privileged role → Secrets Manager | Hand-built (Lambda/Secrets collectors don't exist yet) |
| 4 | Broad Security Group → EC2 → RDS | Real `NetworkAnalyzer`, hand-built RDS asset |
| 5 | Cross-account trust → privileged role | Real `IAMAnalyzer` |
| 6 | Public bucket → sensitive data | Real `NetworkAnalyzer` |
| 7 | `iam:PassRole` privilege escalation | Real `IAMAnalyzer` + full pipeline |
| 8 | Compromised low-priv identity → crown jewel | Real `AttackPathEngine`/`RiskEngine`, entry point = a specific role instead of Internet |

**Honesty about coverage**, stated plainly in the test file's own
docstring rather than glossed over: scenarios 1, 2, 6, 7 exercise real
collector code paths (moto-mocked AWS → `AWSProvider` → `IAMAnalyzer`/
`NetworkAnalyzer`). Scenarios 3, 4, 5, 8 need resource types
(Lambda, RDS, Secrets Manager) that **aren't collected yet** — that's
explicit MVP scope (ARCHITECTURE.md Section 22: "Phase 2: Lambda, RDS,
Secrets Manager, KMS" comes after the MVP). Those four scenarios are
built as hand-constructed `ScanResult` fixtures instead, so the
**downstream engine logic** (graph assembly, path search, risk scoring,
MITRE mapping) is still fully exercised — only the AWS collection layer
for those specific resource types is stubbed. This distinction is
called out in the test file itself, not hidden.

## What this batch caught

This is the test file that surfaced the `CAN_ASSUME`/`TRUSTS` edge
collision bug documented in `docs/PHASE13-15_NOTES.md` — Scenario 2
(IAM user → AssumeRole → Admin role) failed initially because the
`TRUSTS` edge was silently overwriting the `CAN_ASSUME` edge needed for
path traversal. That fix already shipped in the phases 13-15 delivery;
this file is what actually proved it's fixed (all 8 scenarios, including
2, pass now).

## How to run it

```bash
python -m pytest tests/test_synthetic_scenarios.py -v
# or as part of the full suite:
python -m pytest tests/ -v   # 81 tests total as of this phase
```

No Postgres/Redis required for this file specifically — it only
exercises the pure engine layer (Phases 1-7, 14), no persistence.

## Known limitations (intentional, deferred)

1. **Scenarios 3, 4, 5, 8 don't validate real AWS API response shapes**
   for Lambda/RDS/Secrets — only the engine logic once an `Asset` object
   exists. When those collectors get built (post-MVP per the roadmap),
   these scenarios should be upgraded to moto-mocked versions matching
   scenarios 1/2/6/7's pattern, and the hand-built fixtures retired.
2. **No benchmark metrics computed here** (precision/recall/false-positive
   rate) — that's Phase 17 (Benchmarking), which needs this scenario
   suite as its foundation but adds the actual measurement layer on top.
3. **Scenario 1's assertions are looser than the others** (checks the
   pipeline runs and produces sane output, not an exact hop count) —
   moto's exact instance-profile→role resolution shape can vary by moto
   version, so pinning to an exact hop count would make this test
   version-fragile rather than architecture-correct. This is a
   deliberate choice, not an oversight.

## Compatibility check

- All 81 tests pass (73 from phases 1-15 + these 8).
- Confirms the Phase 13-15 `TRUSTS`/`CAN_ASSUME` fix actually works,
  not just in isolation but across every scenario shape in Section 32.
- No scenario here depends on the AI layer, Postgres, or Redis —
  matches the "deterministic engine must work with AI disabled" rule.
