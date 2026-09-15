# Post-v1.0 — Interactive Attack Graph Visualization (Frontend)

## Important: this is a full frontend replacement, not a patch

Unlike the backend (where I gave you a small patch to hand-add), the
`frontend/` folder in this delivery is a **complete reconstruction** of
Dashboard/Assets/AttackPaths plus the new AttackGraph page. This was the
lower-risk choice since the frontend has no security-critical logic the
way `backend/main.py`'s auth does — but **if you'd made any styling or
behavior customizations to your existing pages, they are not preserved
here.** Diff before overwriting if that matters to you.

## What was built

`frontend/src/pages/AttackGraph.tsx` — new page using `@xyflow/react`
(the current, actively-maintained package; `reactflow` is the legacy
name, now effectively deprecated in favor of this one — confirmed by
checking npm directly rather than assuming).

**Features:**
- Full interactive graph: pan, zoom, drag nodes (via React Flow's
  built-in `Controls`)
- Automatic left-to-right layered layout via `@dagrejs/dagre` — chosen
  over a plain force-directed layout because this is fundamentally a DAG
  (Internet → ... → sensitive target), and a layered layout reads far
  more like an actual attack path than a force-directed blob would
- **Nodes/edges on a discovered attack path are color-coded by
  severity** (red=CRITICAL, orange=HIGH, yellow=MEDIUM, gray=LOW) with a
  glow effect and animated edges — the backend's `graph_export.py`
  computes this annotation, the frontend just renders it, matching the
  platform's rule that risk determination never happens client-side
- Asset-type color coding (EC2, S3, RDS, Role, etc.) for anything not on
  an attack path
- "Show only attack paths" toggle to declutter large environments
- Click any node to see a detail panel: id, type, public status, max
  severity, and every relationship touching it
- Minimap for navigating large graphs

## Build verification

```
npm run build
```
Succeeds with **0 TypeScript errors**. One harmless warning: the main
JS bundle is ~500KB (159KB gzipped) — React Flow plus dagre are
legitimately sized dependencies for a graph visualization library, this
isn't a mistake. If bundle size becomes a real concern later, the fix is
route-based code-splitting (dynamic `import()` for the AttackGraph page
specifically, since it's the only page using these heavy deps) — not
attempted here since it wasn't asked for and adds complexity for a
project at this stage.

## Known limitations (intentional, deferred)

1. **No visual difference between edge types beyond the text label** —
   `CAN_PASS_ROLE` and `CONTAINS` render as visually identical arrows
   except for their label text. Distinguishing critical relationship
   types (e.g. dashed for `TRUSTS`, thick solid for `CAN_ASSUME`) would
   improve scanability on dense graphs but wasn't built.
2. **Large graphs (100+ nodes) are untested** — dagre's layout algorithm
   should scale fine, but the rendering/interaction performance at real
   production-account scale (hundreds of assets) hasn't been verified,
   since this was built and tested against small hand-constructed
   scenarios, not a large synthetic account.
3. **No edge-click detail** — clicking a node shows its relationships in
   the side panel, but clicking an edge directly doesn't do anything yet
   (Section 24 of the original design calls for this: "Clicking an edge
   should show relationship/evidence/source/permission/policy/confidence").
   The data is already in the payload (`evidence`, `confidence` per edge
   from `backend/graph_export.py`) — wiring up an edge-click handler is a
   small follow-up, not a redesign.
4. **No "focus on crown jewel" or path-highlighting-on-hover** — also
   called out in the original design, not built here. The severity
   color-coding gets you most of the way to "see what's dangerous at a
   glance" without it.

## Compatibility check

- `frontend/src/lib/api.ts`'s existing functions (`createScan`,
  `listAssets`, `listAttackPaths`, `getStatistics`) are unchanged — only
  `getGraph()` was added.
- No changes to `Dashboard.tsx`, `Assets.tsx`, `AttackPaths.tsx` beyond
  what's needed to keep them working (they're identical in behavior to
  before, just re-typed from scratch after the sandbox reset).
- New dependencies added: `@xyflow/react`, `@dagrejs/dagre` — both
  widely-used, actively-maintained packages, versions pinned in
  `package.json`/`package-lock.json`.
