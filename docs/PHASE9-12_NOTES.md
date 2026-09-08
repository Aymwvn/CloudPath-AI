# Phases 9–12 — Implementation Notes

## What was built

**Phase 9 — PostgreSQL Persistence**
`backend/db/models.py` — SQLAlchemy models for the MVP subset of
ARCHITECTURE.md Section 16's schema (cloud_accounts, scan_jobs, assets,
relationships, findings, attack_paths, attack_path_steps, ai_analysis,
crown_jewels). `backend/db/store.py` (`PostgresScanStore`) implements the
exact same interface as Phase 8's `InMemoryScanStore` — `save()`,
`get()`, `latest()` — and **fully rehydrates a working `ScanRecord`**
(including a live, queryable `GraphEngine`) from persisted rows via
`backend/db/queries.py::rebuild_scan_record`, not just a partial data
projection. Real Alembic migration generated and applied against an
actual Postgres 16 instance (`migrations/versions/`).

**Phase 10 — Background Workers**
`backend/tasks/celery_app.py` + `backend/tasks/scan_tasks.py`. `POST
/api/v1/scans/async` now returns immediately (202) with a `pending`
scan_id while `run_scan_task` does the real work and updates the job row
through `pending → running → completed`/`failed` — matches
ARCHITECTURE.md Section 30 ("a scan should not block an HTTP request").
The original synchronous `POST /api/v1/scans` (Phase 8) is kept
unchanged for local/demo use.

**Phase 11 — React Dashboard**
Vite + React + TypeScript + Tailwind v4 app in `frontend/`. Three real
pages (Dashboard, Assets, Attack Paths) backed by the actual API — no
fabricated data for endpoints that don't exist yet. `npm run build`
verified clean, 0 TypeScript errors.

**Phase 12 — AI Abstraction Layer**
`ai/providers/` — `LLMProvider` interface with `AnthropicProvider`,
`OpenAICompatibleProvider` (also covers Ollama via its OpenAI-compat
endpoint), and `MockProvider` for offline testing. `ai/prompt.py` builds
the evidence-first prompt with explicit `<UNTRUSTED_CLOUD_DATA>`
delimiters around anything that traces back to scanned cloud resource
names/tags/policies (Section 17). `ai/schema.py` + `ai/explainer.py`
validate every response against the exact JSON schema from Section 18,
with one retry on invalid output before giving up (never surfaces
unvalidated data).

## Bugs found and fixed during testing (against real infrastructure)

This batch was tested against **real Postgres and real Redis**, not just
mocks — that's what surfaced these:

1. **`Asset.id` can't be a database primary key.** Natural asset ids
   like `"aws:internet"` repeat across every single scan (every account
   has one). Making it the PK meant a second scan would collide on
   INSERT. Fixed by adding a synthetic `pk` column and moving the
   natural id to a non-unique `asset_id` column, scoped by `scan_job_id`.
   This is exactly the kind of bug that only shows up against a real
   database — SQLite/mocks wouldn't have caught it the same way if the
   test data happened to use unique-looking ids by coincidence.
2. **Double-save on the async path.** The Celery task originally called
   `store.save(record)` itself *after* `ScanService.run_scan()` already
   saved internally, which would have inserted every asset/relationship/
   attack-path row twice. Fixed by removing the redundant call and
   documenting why in the task's comment.
3. **`get_scan`'s Postgres fallback wasn't exception-safe at query time.**
   `_postgres_store()` only fails if the store object can't be
   *constructed* — but SQLAlchemy's `sessionmaker` is lazy, so
   construction always succeeds even with Postgres down; the connection
   error only happens when `.get()` actually runs a query. The original
   code wrapped construction in try/except but not the `.get()` call
   itself, so a downed Postgres would 500 instead of cleanly falling
   through to 404. Verified by actually stopping the Postgres service
   mid-test-run and confirming the endpoint still degrades gracefully.

## How to run it

```bash
pip install -r requirements.txt

# Postgres + Redis (docker-compose.yml covers this for normal use;
# for bare-metal: `service postgresql start`, `redis-server --daemonize yes`)
createdb cloudpath
alembic upgrade head

python -m pytest tests/ -v   # 53 tests; Postgres-dependent ones skip cleanly if it's not reachable

# backend
uvicorn backend.main:app --reload

# frontend
cd frontend && npm install && npm run dev
```

## Known limitations (intentional, deferred)

1. **AI layer isn't wired into the scan pipeline yet.** `ai/explainer.py`
   works and is tested end-to-end with `MockProvider`, but
   `ScanService`/`backend/main.py` don't call it yet — no
   `POST /api/v1/attack-paths/{id}/analyze` endpoint exists. That's next.
2. **`factor_breakdown` isn't persisted** — `AttackPathModel` stores the
   final `risk_score`/`severity`/`confidence` but not the per-factor
   math that produced them. Rehydrated `RiskAssessment` objects have an
   empty `factor_breakdown`. Cheap to add as a JSON column later.
3. **No real multi-account isolation enforcement yet** — `cloud_accounts`
   table exists but nothing queries scoped by it; every endpoint
   currently assumes a single implicit account (fine for MVP single-
   tenant use, not for Section 26's multi-account model).
4. **Frontend has no Attack Graph visualization** — see
   `docs/PHASE11_NOTES.md` for why this was deferred and what unblocks it.
5. **`OpenAICompatibleProvider`/`AnthropicProvider` are untested against
   real APIs in this test run** (no API keys available in this
   environment) — they're tested for import-safety and interface
   correctness only. `MockProvider` carries all the real logic testing
   (prompt construction, injection defense, schema validation, retry).

## Compatibility check

- `PostgresScanStore` and `InMemoryScanStore` are interchangeable from
  `ScanService`'s point of view — no phase 8 code changed.
- AI layer only ever receives finalized `AttackPath`/`RiskAssessment`
  objects — no raw AWS data, no write access, matching Section 3's core
  architecture rule ("AI is an analysis and explanation layer" only).
- Frontend only calls endpoints that exist and are tested.
- All 53 tests pass; 7 gracefully skip when Postgres isn't reachable
  rather than failing CI in environments without it configured.

## Next up: wiring the AI layer into the API + real per-path detail

`POST /api/v1/attack-paths/{id}/analyze` (Section 27) should call
`AttackPathExplainer`, persist the result via `AIAnalysisModel`, and
`GET /api/v1/attack-paths/{id}` (single-path detail — doesn't exist yet,
only the list endpoint does) should return it — this is also what
unblocks the Attack Graph frontend page and the "Attack Path
Investigation" page from Section 25.
