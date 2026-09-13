# Phase 20 — v1.0.0 Release Notes

## Release verification performed

Before tagging v1.0.0, the following was actually checked (not assumed):

1. **Full migration history applied to a completely fresh database** —
   dropped and recreated a new Postgres database, ran `alembic upgrade
   head` from scratch, confirmed all 3 migrations apply cleanly in order
   (`initial schema` → `add mitre_techniques table` → `add users and
   audit_logs tables`) and produce all 12 expected tables.
2. **Full test suite run fresh, verbose, against real infrastructure** —
   113/113 tests passing, 0 skipped (both Postgres and Redis were
   reachable for this run), confirmed line-by-line in verbose mode
   rather than trusting a summary count alone.
3. **Benchmark harness regenerated** — `python -m benchmarks.run_benchmark`
   re-run fresh; results unchanged from Phase 17 (1.00 F1 across all
   metrics, hallucination checker correctly distinguishing 0%/100%).
4. **Frontend rebuilt from a clean `node_modules` install** — confirmed
   `npm install && npm run build` still succeeds with zero TypeScript
   errors after the version bump to 1.0.0.
5. **Version numbers bumped consistently** — `backend/main.py`'s FastAPI
   `version="1.0.0"`, `frontend/package.json`'s `"version": "1.0.0"`.

## What v1.0.0 means here

This tags the point where all 20 originally-planned phases from
`docs/ARCHITECTURE.md` are complete. It does **not** mean the platform
is feature-complete against the full aspirational spec in that document,
and it does not mean every corner has been battle-tested against real
production AWS accounts. See the README's feature table and
`CHANGELOG.md`'s "Known limitations at v1.0" section for the honest
accounting of what's genuinely done vs. what's explicitly deferred —
Lambda/RDS/Secrets/KMS collection, a standalone CLI, multi-cloud
support, and tenant isolation enforcement are the biggest ones.

## Tagging the release

```bash
git add -A
git commit -m "chore: v1.0.0 release - version bump, changelog, final verification"

git tag -a v1.0.0 -m "CloudPath AI v1.0.0 - all 20 planned phases complete, 113 tests passing"
git push origin main --tags
```

Then create a GitHub Release from that tag (Releases → Draft a new
release → choose the `v1.0.0` tag) and paste in the `[1.0.0]` section of
`CHANGELOG.md` as the release notes — GitHub renders that markdown
directly, no need to write a separate release description from scratch.

## Suggested next steps after v1.0.0 (not part of this release)

In rough priority order based on what would most improve real-world
usefulness, per the gaps documented throughout this project:

1. Lambda/RDS/Secrets Manager/KMS collectors (unlocks the 4 synthetic
   scenarios currently using hand-built fixtures instead of real moto
   calls — see `docs/PHASE16_NOTES.md`)
2. Tenant/multi-account data isolation enforcement (currently the
   single biggest security gap for any multi-account use — see
   `SECURITY.md`'s Known Gaps)
3. Interactive attack graph visualization in the frontend (React Flow,
   as originally scoped in `docs/ARCHITECTURE.md` Section 24)
4. Actually build and verify the Docker Compose setup end-to-end with a
   real Docker daemon — this is the one piece of Phase 18 that was
   written but never executed
5. A real standalone `cloudpath` CLI (Section 35 of the original design;
   `scripts/run_scan_demo.py` is a demo, not the real thing)
