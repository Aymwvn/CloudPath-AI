# Phase 11 — React Dashboard Notes

## What was built

Vite + React + TypeScript app in `frontend/`, styled with Tailwind v4
(via `@tailwindcss/vite` — no separate postcss.config needed, that's the
new v4 way). Dev server proxies `/api/*` to `http://localhost:8000` so
the frontend and FastAPI backend need no CORS configuration locally.

**Pages implemented** (matching a subset of ARCHITECTURE.md Section 23 —
only the ones with a real backend endpoint behind them):
- **Dashboard** (`src/pages/Dashboard.tsx`) — trigger a scan, see asset/
  relationship/attack-path counts and type breakdowns.
- **Assets** (`src/pages/Assets.tsx`) — filterable/searchable table of
  discovered assets.
- **Attack Paths** (`src/pages/AttackPaths.tsx`) — ranked list (by risk
  score) with expandable step-by-step evidence, severity badges, and a
  "POTENTIAL" tag for paths below the confidence threshold.

`src/lib/api.ts` is a typed client covering exactly what `backend/main.py`
exposes today — it does **not** fabricate calls to endpoints that don't
exist yet (findings, MITRE, what-if simulation, crown jewels CRUD).

## Deliberately deferred

- **Attack Graph page (interactive React Flow visualization)** —
  Section 24 of ARCHITECTURE.md calls for this explicitly, but it's a
  substantial standalone piece (node/edge rendering, click-to-inspect,
  zoom/pan/filter). Scaffolding the simpler list-based pages first let
  every page here be backed by a real, tested endpoint rather than
  guessing at a graph payload shape before Phase 9's persistence layer
  settled. Next natural slot for this: right after Phase 9's
  `GET /api/v1/attack-paths/{id}` (single-path detail) exists, since the
  graph view needs per-path node/edge data, not just the list view.
- **IAM Analysis / Network Analysis / Findings / MITRE / Crown Jewels /
  Reports / Settings / Audit Logs pages** — no backend endpoint serves
  these yet (findings aren't exposed via the API at all currently, only
  computed and folded into attack path evidence). Sidebar has an honest
  note about this rather than showing empty/fake pages.
- **Auth UI** — no login screen, since the backend has no auth yet
  either (Phase 18: security hardening).

## How to run it

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
npm run build       # production build — verified clean, 0 TypeScript errors
```

Run the backend alongside it (`uvicorn backend.main:app --reload` from
the repo root) for the Dashboard's "Run Scan" button to actually work.

## Compatibility check

- Only consumes endpoints that exist and are tested (Phase 8/10).
- No new backend contract assumed — if `AssetOut`/`AttackPathOut` schemas
  change in `backend/schemas.py`, `src/lib/api.ts` types need a matching
  update (not yet automated/shared — a natural candidate for an OpenAPI-
  generated client in a later phase, noted here rather than silently
  left as a maintenance trap).
