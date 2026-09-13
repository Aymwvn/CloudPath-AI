# Changelog

## [1.0.0] — v1.0 Release (Phase 20)

First tagged release. Built incrementally across 20 phases, each tested
against real infrastructure (real Postgres, real Redis, moto-mocked AWS)
wherever the phase touched persistence, queuing, or cloud APIs — not
just unit-tested in isolation. **113 tests passing** at release time,
verified fresh against a clean database with the full migration history
applied from scratch.

### Added

- **Phase 1** — Read-only AWS collectors (IAM, EC2, S3, VPC, Security Groups)
- **Phase 2** — Asset normalization and structural relationship graph model
- **Phase 3** — IAM effective-permission engine (explicit-deny-aware, not naive wildcard matching)
- **Phase 4** — Network exposure analysis (security groups, real S3 public-access determination)
- **Phase 5** — Graph Engine (NetworkX-based assembly, instance-profile→role resolution)
- **Phase 6** — Attack Path Engine (k-shortest-paths search, entry points to crown jewels)
- **Phase 7** — Risk Engine (weighted scoring, risk and confidence tracked independently)
- **Phase 8** — FastAPI backend (MVP REST API, in-memory scan store)
- **Phase 9** — PostgreSQL persistence with full scan record rehydration
- **Phase 10** — Celery + Redis background scanning (pending → running → completed lifecycle)
- **Phase 11** — React + TypeScript + Tailwind dashboard
- **Phase 12** — AI abstraction layer (Anthropic/OpenAI/Ollama-compatible), evidence-first prompting with proven prompt-injection defense
- **Phase 13** — AI analysis wired into the API (`POST /attack-paths/{id}/analyze`)
- **Phase 14** — Deterministic MITRE ATT&CK mapping
- **Phase 15** — What-if remediation simulation
- **Phase 16** — 8 canonical synthetic attack scenario tests
- **Phase 17** — Benchmarking harness (precision/recall/F1, AI hallucination-rate checker)
- **Phase 18** — JWT auth, RBAC (viewer/analyst/admin), rate limiting, audit logging, Docker hardening
- **Phase 19** — README, SECURITY.md, CONTRIBUTING.md, LICENSE
- **Phase 20** — Version 1.0.0 tag, this changelog, final release verification

### Fixed (real bugs caught during development, not hypothetical)

- `CAN_ASSUME`/`TRUSTS` edges silently colliding in the graph — `DiGraph`
  can only hold one edge per node pair; fixed by not emitting both for
  the same relationship (Phase 13-16 notes)
- Risk scoring formula dividing by 100 twice, making a maxed-out CRITICAL
  path score `1/100` instead of `~86/100` (Phase 5-8 notes)
- `Asset.id` used as a database primary key, which collided across scans
  since ids like `"aws:internet"` repeat in every account (Phase 9-12 notes)
- Double-save on the async scan path that would have duplicated every
  row on each background scan (Phase 9-12 notes)
- `get_scan`'s Postgres fallback not being exception-safe at query time,
  only at store-construction time — verified by literally stopping
  Postgres mid-test-run (Phase 9-12 notes)
- `passlib` + current `bcrypt` versions are incompatible — switched to
  `bcrypt` directly, verified before building auth on top of it (Phase 18 notes)
- Rate limiter breaking test isolation via a fixed test username
  accumulating real Redis state across repeated runs — fixed with
  unique per-run usernames, verified by running the affected tests 3
  times in a row (Phase 18 notes)

### Known limitations at v1.0 (see individual `docs/PHASE*_NOTES.md` for full detail)

- No standalone `cloudpath` CLI (only a demo script, `scripts/run_scan_demo.py`)
- Lambda, RDS, Secrets Manager, and KMS are not collected (IAM/EC2/S3/VPC/SG only)
- No interactive attack graph visualization in the frontend (list/table views only)
- No multi-cloud support (AWS only; `providers/` structure supports future Azure/GCP)
- No tenant/multi-account data isolation enforcement
- No JWT revocation before natural token expiry
- Docker Compose setup is written to best practices but **not verified
  by execution** — no Docker daemon was available during development
- Benchmarking (Phase 17) is a regression detector against hand-traced
  ground truth, not independent real-world accuracy validation

See [`README.md`](README.md) for the full up-to-date feature status table.
