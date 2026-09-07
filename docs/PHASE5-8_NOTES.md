# Phases 5–8 — Implementation Notes

## What was built

**Phase 5 — Graph Engine**
`engine/graph/builder.py` (`GraphEngine`) assembles `Asset`/`Relationship`
records into an in-memory NetworkX `DiGraph`. Construction is kept
separate from traversal/ranking (ARCHITECTURE.md Section 29) so a later
swap to Neo4j only touches this file. This phase also **fixes Known
Limitation #1** from the Phase 1-4 notes: `collectors.collect_instance_profiles()`
now maps instance-profile name → role name, and `GraphEngine._resolve_instance_profile_edges()`
rewrites the approximate `RUNS_AS` edge into an exact role edge at
confidence 1.0 when the mapping is available.

**Phase 6 — Attack Path Engine**
`engine/attack_paths/engine.py` (`AttackPathEngine`) runs
`nx.shortest_simple_paths` (Yen's algorithm) from entry points (Internet
+ anything public) to targets (declared crown jewels, or a default
heuristic set: RDS/S3/Secrets/KMS), bounded by `max_depth` (default 8)
and capped at `max_paths_per_pair` (default 5) per ARCHITECTURE.md
Section 12. Paths are marked `"path"` only if every edge meets a minimum
confidence threshold (default 0.5) — otherwise `"potential_path"`.

**Phase 7 — Risk Engine**
`engine/risk/engine.py` (`RiskEngine`) scores each `AttackPath` 0-100
using the exact weighted factors from ARCHITECTURE.md Section 14
(internet-reachable, crown-jewel target, privilege escalation, cross-
account, path length, missing controls, sensitive data), banded into
LOW/MEDIUM/HIGH/CRITICAL. **Risk and confidence are computed and reported
as two independent numbers** (Section 13) — confidence comes straight
from `AttackPath.average_confidence`, completely separate from the risk
factor math.

**Phase 8 — FastAPI Backend (MVP subset)**
`backend/main.py` exposes `POST /api/v1/scans`, `GET /api/v1/scans/{id}`,
`GET /api/v1/assets`, `GET /api/v1/attack-paths`, `GET /api/v1/statistics`,
`GET /health`. `backend/scan_service.py` wires phases 1-7 together
end-to-end synchronously. Results are held in `InMemoryScanStore` —
**explicitly a placeholder**, not the real persistence layer (that's
Phase 9/PostgreSQL). No auth/RBAC yet (Phase 18: security hardening).

## Bugs found and fixed during testing

1. **Attack Path Engine swallowed no-path cases incorrectly at first.**
   `nx.shortest_simple_paths()` raises `NetworkXNoPath` *lazily*, while
   the generator is being iterated — not when it's first called. The
   original code wrapped only the call in `try/except`, so the exception
   escaped uncaught during iteration. Fixed by wrapping the entire
   consuming loop.
2. **Risk score formula was wrong by a factor of 100.** Original code did
   `factor * (weight / 100)`, which (since weights already sum to 100)
   silently divided every contribution by 100 twice, making a maxed-out
   critical path score `1/100` instead of `~86/100`. Caught by
   `test_escalation_path_scores_high_or_critical` actually asserting on a
   real expected severity band instead of just "did it run without
   crashing." Fixed to `factor * weight` directly.

Both were caught by the test suite before shipping — this is exactly why
Section 32/33 of ARCHITECTURE.md insist on synthetic scenario testing
before trusting the engine's output.

## How to run it

```bash
pip install -r requirements.txt
python -m pytest tests/ -v          # 35 tests, fully offline (moto-mocked AWS)

# run the API locally
uvicorn backend.main:app --reload
# then POST http://127.0.0.1:8000/api/v1/scans  (needs real AWS creds configured)
# interactive docs at http://127.0.0.1:8000/docs
```

## Known limitations (intentional, deferred)

1. **In-memory store only** — restarting the API loses all scan history.
   Real persistence is Phase 9.
2. **Synchronous scanning** — `POST /api/v1/scans` blocks until the scan
   finishes. Background job workers (Celery/Redis) are Phase 9/30.
3. **`cross_account` risk factor is a crude string-match heuristic**
   (`"account" in str(evidence)`) rather than actually comparing account
   IDs in the trust statement principal — fine for MVP, should be
   tightened when Phase 9 adds proper multi-account modeling (Section 26).
4. **No auth on the API yet** — anyone who can reach the FastAPI process
   can trigger a scan. Fine for local/demo use, not fine for anything
   further (Phase 18: security hardening covers this explicitly).
5. **`default_targets()` treats every S3 bucket as a potential target**,
   not just ones flagged sensitive — intentional per Section 14 ("a
   bucket doesn't have to be pre-flagged sensitive to be worth reaching"),
   but means path counts will look noisy on accounts with many buckets
   until declared crown jewels are used instead.

## Compatibility check against ARCHITECTURE.md and Phases 1-4

- Graph/edge vocabulary unchanged — no new node/edge types introduced.
- `GraphEngine` never imports anything AWS-specific — respects the
  `CloudProvider` abstraction boundary.
- Attack Path Engine and Risk Engine only consume the graph +
  `AttackPath` objects — no AI/LLM call anywhere in this phase range,
  matching the "deterministic engine discovers, AI only explains" rule
  (Section 3).
- All phase 1-4 tests still pass unmodified — nothing here changed their
  contracts, only added the instance-profile resolution as an *additive*
  correction path.

## Next up: Phase 9 (PostgreSQL persistence)

Replace `InMemoryScanStore` with real tables (Section 16 schema),
add Alembic migrations, and move scan execution behind a Celery worker
so `POST /api/v1/scans` returns immediately with a `scan_id` while the
work happens in the background — this is also where the `scan_jobs`
status tracking becomes real instead of always being `"completed"`.
