# Phases 13–15 — Implementation Notes

## What was built

**Phase 13 — Evidence-First AI wired into the API**
`backend/ai_service.py` (`AIAnalysisService`) loads a *persisted*
attack path by its real Postgres row id, reconstructs the
`AttackPath`/`RiskAssessment` objects, runs them through Phase 12's
`AttackPathExplainer`, and persists the validated result to
`AIAnalysisModel`. New endpoints in `backend/main.py`:
- `POST /api/v1/attack-paths/{id}/analyze` — runs (or re-runs) analysis
- `GET /api/v1/attack-paths/{id}/analysis` — reads back a prior result
  without calling the LLM again

This only works against Postgres-persisted attack paths (i.e. scans run
via `/api/v1/scans/async`, Phase 10) — the in-memory/synchronous scan
path has no stable path ids to attach an `AIAnalysisModel` row to. This
is a real, intentional limitation, not an oversight.

**Phase 14 — MITRE ATT&CK Mapping**
`mitre/mapper.py` (`MitreMapper`) — fully deterministic, no AI involved.
Maps specific graph `edge_type`s to techniques (`EXPOSED_TO` →
T1190/T1133, `CAN_ASSUME`/`TRUSTS` → T1078.004, `CAN_PASS_ROLE` →
T1098.003) and target node types to techniques (S3/RDS → T1530, Secret →
T1552.005) — never inferred from AI output, per ARCHITECTURE.md Section
19's "only map when evidence supports it." Computed and persisted
automatically in `PostgresScanStore.save()` via a new `MitreTechniqueModel`
table (new Alembic migration applied and verified against real Postgres).
Exposed via `GET /api/v1/attack-paths/{id}/mitre`.

**Phase 15 — What-If Remediation Simulation**
`engine/attack_paths/whatif.py` (`WhatIfSimulator`) — removes a given
set of edges from a **copy** of the graph (never mutates the original)
and recomputes attack paths, diffing before/after to show which paths
get blocked vs. stay open. Exposed via `POST /api/v1/simulation`
(ARCHITECTURE.md Section 27/21).

## A real bug this batch caught (not a test typo)

While building Phase 16's synthetic scenario tests, one exposed a
genuine architectural bug in **Phase 5's Graph Engine**, not just a bad
assertion:

**`GraphEngine` uses a plain `nx.DiGraph`, which can only hold ONE edge
between any two nodes.** `engine/iam/analyzer.py`'s trust-policy analysis
was emitting both a `CAN_ASSUME` edge and a `TRUSTS` edge for the same
`(source, target)` pair whenever an AWS-principal trust statement was
found. In a `DiGraph`, the second `add_edge()` call for the same pair
**silently overwrites the first** — no error, no warning, just quietly
losing the `CAN_ASSUME` edge (the one attack-path search actually needs)
in favor of `TRUSTS` (which was added second).

I checked whether switching to `nx.MultiDiGraph` (which supports
parallel edges) was the fix — it isn't: `nx.shortest_simple_paths`
(the algorithm the Attack Path Engine, Phase 6, depends on) explicitly
does not support multigraphs (confirmed by testing it directly, not by
reading docs and assuming).

**The actual fix:** stop emitting the redundant `TRUSTS` edge for
AWS-principal trust statements — `CAN_ASSUME` already conveys that
relationship for attack-path purposes. `TRUSTS` is still emitted for
service-principal trust (`ec2.amazonaws.com`, etc.), where there's no
`CAN_ASSUME` collision risk since service principals never get a
`CAN_ASSUME` edge in the first place.

This is a one-file fix (`engine/iam/analyzer.py`) but it's a real
correctness issue that's been present since Phase 3 — every scan run
before this fix could have silently dropped `CAN_ASSUME` edges wherever
a role's trust policy also matched the `TRUSTS`-emitting code path,
meaning some real escalation paths could have gone undetected. Worth
re-running any scans you've already done against a fresh build.

## How to run it

```bash
pip install -r requirements.txt
alembic upgrade head    # picks up the new mitre_techniques table
python -m pytest tests/ -v
```

No new endpoints require new environment variables beyond what Phase 12
already needs (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
`OPENAI_BASE_URL` for the `/analyze` endpoint specifically — everything
else works without any AI provider configured).

## Known limitations (intentional, deferred)

1. **`GET /api/v1/attack-paths/{id}` (single-path detail, distinct from
   the list endpoint)** doesn't exist yet — the new `/analyze` and
   `/mitre` endpoints take a path id directly, but there's no endpoint
   yet that returns one path's full detail (steps + risk + MITRE + AI
   analysis) in a single response. Natural next step.
2. **What-if simulation only works against in-memory (synchronous)
   scans right now** (`service.store`), not Postgres-persisted async
   scans — `WhatIfSimulator` itself is storage-agnostic (it just needs a
   `ScanResult`), so wiring it to also accept a Postgres-persisted
   `scan_id` is a small follow-up, not a redesign.
3. **MITRE mapping ruleset is intentionally small** — 4 edge-type rules
   + 3 target-type rules, covering the specific techniques
   ARCHITECTURE.md Section 19 names as examples. Expanding coverage
   (e.g. mapping `RUNS_AS`, `CONTAINS`, cross-account `CAN_ASSUME`
   specifically to T1199/T1078 variants) is straightforward additive
   work against the same `EDGE_TYPE_TECHNIQUES`/`TARGET_TYPE_TECHNIQUES`
   dictionaries.

## Compatibility check

- All 81 tests pass (73 from phases 1-12 + 8 synthetic scenarios that
  surfaced and validated the analyzer fix above).
- AI layer still only ever receives finalized, persisted attack path
  data — the new `/analyze` endpoint doesn't change that contract.
- MITRE mapping computed at persist time, fully separate from the AI
  layer — matches Section 3's deterministic-engine-first architecture.
- What-if simulation never mutates the original graph or scan data —
  explicitly tested (`test_original_graph_is_not_mutated_by_simulation`).
