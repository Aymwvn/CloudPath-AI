# CloudPath AI

**AI-Powered Cloud Attack Path Analyzer**

> "Discover how cloud weaknesses can be chained into real attack paths."

CloudPath AI is a defensive, open-source cloud security platform. Instead of reporting cloud misconfigurations as an isolated flat list (the way most scanners do), it builds a graph of your cloud environment, finds the actual chains an attacker could walk from the internet to your sensitive data, ranks those paths by real risk, and uses AI **only** to explain findings a deterministic engine already discovered — never to invent them.

**Project status: v1.0.0 — all 20 planned phases complete.** See [`CHANGELOG.md`](CHANGELOG.md) for the full release history and [Roadmap](#roadmap) below for what's built vs. known gaps beyond the original plan — this is a v1.0 with honestly-documented limitations, not a claim of completeness.

---

## The problem

Cloud scanners (Prowler, ScoutSuite, native AWS tools) report findings in isolation:
- "S3 bucket X is public"
- "IAM role Y has `*` permissions"
- "Security group Z allows `0.0.0.0/0`"

Individually, none of these tells you what actually matters: **can these weaknesses be chained together into a real path to something valuable?** CloudPath AI answers that question directly — "given what's exposed, what's the shortest way to my production database?" — rather than making you manually correlate hundreds of flat findings yourself.

## How it's different

The deterministic graph/security engine discovers attack paths. AI only explains and summarizes what the engine already found — it never invents a finding, never gets to add a step to a path, and the system produces useful output even with AI fully disabled. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design rationale (written before any code — Phase 0 of this project).

## What's actually built (Phases 1–18)

| Area | Status | Where |
|---|---|---|
| AWS discovery (IAM, EC2, S3, VPC, Security Groups) | ✅ | `providers/aws/` |
| Asset normalization + graph assembly | ✅ | `engine/models.py`, `engine/graph/` |
| IAM effective-permission analysis | ✅ | `engine/iam/` |
| Network exposure analysis | ✅ | `engine/network/` |
| Attack path discovery (k-shortest-paths) | ✅ | `engine/attack_paths/engine.py` |
| Risk + confidence scoring | ✅ | `engine/risk/` |
| REST API (FastAPI) | ✅ | `backend/main.py` |
| PostgreSQL persistence | ✅ | `backend/db/` |
| Background scanning (Celery + Redis) | ✅ | `backend/tasks/` |
| React dashboard | ✅ | `frontend/` |
| AI abstraction layer (Anthropic/OpenAI/Ollama) | ✅ | `ai/` |
| Evidence-first AI wired into the API | ✅ | `backend/ai_service.py` |
| MITRE ATT&CK mapping (deterministic) | ✅ | `mitre/` |
| What-if remediation simulation | ✅ | `engine/attack_paths/whatif.py` |
| Synthetic scenario test suite | ✅ | `tests/test_synthetic_scenarios.py` |
| Benchmarking harness | ✅ | `benchmarks/` |
| Auth, RBAC, rate limiting, audit logs | ✅ | `backend/auth.py`, `backend/rate_limit.py` |
| Docker hardening | ⚠️ built, **not verified by execution** — see `docs/PHASE18_NOTES.md` |
| Documentation (README, SECURITY, CONTRIBUTING) | ✅ | this file, `SECURITY.md`, `CONTRIBUTING.md` |
| **v1.0.0 release** | ✅ | see `CHANGELOG.md` |
| Standalone `cloudpath` CLI | ❌ not built — `scripts/run_scan_demo.py` is a demo script only, not the full CLI described in the original design |
| Lambda / RDS / Secrets Manager / KMS collection | ❌ not built (explicit post-MVP scope) |
| Interactive attack graph visualization (React Flow) | ❌ not built — dashboard currently shows list/table views only |
| Multi-cloud (Azure/GCP) | ❌ not built — `providers/` structure supports it, no implementation |

**113 tests passing** as of Phase 18, run against real Postgres and Redis instances (not just mocks) wherever persistence/queuing is involved.

## Architecture

```
AWS API → Collectors → Asset Inventory → Relationship Builder
                                              ↓
                            IAM Engine ─→ Graph Engine ←─ Network Engine
                                              ↓
                                     Attack Path Engine
                                              ↓
                                    Risk / Confidence Engine
                                        ↓           ↓
                                  MITRE Mapper   AI Explanation Layer
                                              ↓
                          FastAPI Backend ←→ PostgreSQL + Redis
                                ↓
                          React Dashboard
```

Full detail, including the graph data model, IAM evaluation logic, risk-scoring formula, and threat model: see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Example attack path

```
Internet
  ↓ (EXPOSED_TO)
Public EC2 Instance
  ↓ (RUNS_AS)
WebServerRole
  ↓ (CAN_PASS_ROLE)
HighPrivilegeRole
  ↓ (CAN_READ)
Production S3 Bucket
```

Risk: **HIGH** (score 72/100) · Confidence: **0.95** · MITRE: T1190, T1133, T1098.003, T1530

*(This exact score was verified by running the real `RiskEngine` against this exact scenario shape, not written by hand — see the shape in `tests/test_synthetic_scenarios.py::TestScenario2AssumeRoleToAdmin` for a closely related example.)*

## Installation

### Local (no Docker)

```bash
git clone https://github.com/Aymwvn/CloudPath-AI.git
cd CloudPath-AI
pip install -r requirements.txt

# Postgres + Redis (bare-metal example; use docker-compose for a managed setup)
createdb cloudpath
alembic upgrade head

export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python scripts/create_admin.py --username admin   # prompts for a password

uvicorn backend.main:app --reload
```

Frontend:
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, proxies /api to :8000
```

### Docker

```bash
cp .env.example .env   # fill in POSTGRES_PASSWORD and JWT_SECRET_KEY
docker compose up --build
docker compose exec backend python scripts/create_admin.py --username admin
```

**Note:** the Docker setup is written to security best practices (non-root containers, resource limits, isolated networking — see `docs/PHASE18_NOTES.md`) but has not been verified by actually running it in this project's development environment. Confirm it works for you before relying on it.

## AWS permissions required

Read-only, least-privilege. Never requires write/mutating permissions. Full policy JSON: see `docs/ARCHITECTURE.md` Section 10. Summary: `iam:List*`/`Get*`, `ec2:Describe*`, `s3:ListAllMyBuckets`/`GetBucket*`, `sts:GetCallerIdentity`.

## Authentication

Three roles: `viewer` (read-only) < `analyst` (can trigger scans/simulations) < `admin` (can create users). Get a token:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin&password=yourpassword"
```

Use the returned `access_token` as `Authorization: Bearer <token>` on every other request.

## AI configuration

Set **one** of these environment variables to enable `POST /api/v1/attack-paths/{id}/analyze`:
- `ANTHROPIC_API_KEY` — uses Claude
- `OPENAI_API_KEY` — uses OpenAI
- `OPENAI_BASE_URL` (e.g. `http://localhost:11434/v1`) — uses a local Ollama model

Without any of these set, everything else in the platform still works — the deterministic engine (discovery, graph, attack paths, risk, MITRE) never depends on AI being configured.

## Testing

```bash
python -m pytest tests/ -v
```

113 tests as of Phase 18. Tests requiring Postgres/Redis skip cleanly (not fail) if those aren't reachable. See `docs/PHASE16_NOTES.md` for the 8 canonical synthetic attack scenarios this project validates against.

## Benchmarking

```bash
python -m benchmarks.run_benchmark
```

Writes `docs/benchmarks.md`. Read `docs/PHASE17_NOTES.md` for an honest description of what this benchmark does and doesn't prove — it's currently a regression detector against hand-traced ground truth, not independent real-world accuracy validation.

## Security model

See [`SECURITY.md`](SECURITY.md) for the full threat model, RBAC design, and vulnerability reporting process.

## Roadmap

**All 20 originally-planned phases are complete as of v1.0.0** — see
[`CHANGELOG.md`](CHANGELOG.md) for the full phase-by-phase history and
every real bug caught and fixed along the way.

**Known gaps beyond the original 20-phase plan** (not hidden, tracked honestly): standalone CLI, Lambda/RDS/Secrets/KMS collection, interactive attack graph UI, multi-cloud support, tenant isolation enforcement, JWT revocation. See each phase's `docs/PHASE*_NOTES.md` for the specific limitations recorded at the time that phase was built.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](LICENSE).
