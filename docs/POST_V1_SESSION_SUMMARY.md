# Post-v1.0 — Session Summary (Security Hardening + Coverage Round 2)

This ties together everything added after the v1.0.0 tag across this
round of work. Each item has its own detailed notes file, linked below
— this is the index, not a replacement for them.

## What was added

| Area | What | Notes file |
|---|---|---|
| AWS collection | Lambda VPC config → SG correlation eligibility | `docs/POST_V1_KMS_LAMBDA_EBS_NOTES.md` |
| AWS collection | EBS volume encryption → EC2 `ENCRYPTED_BY` edges | same |
| Graph accuracy | Egress-aware confidence on SG-to-SG `CONNECTED_TO` edges | same |
| Auth | JWT revocation (Redis blocklist, fail-open by design) | `docs/POST_V1_REVOCATION_AUDIT_TENANT_PATCH.md` |
| Security | Tenant isolation — per-account access control, default-deny | same |
| Observability | `GET /api/v1/audit-logs` endpoint | same |
| Frontend | Edge-click detail panel in the attack graph (evidence, confidence) | — |
| CLI | `cloudpath scan wait <id>` — blocking poll for async scans | — |

**Test count added this round: 33** (7 collector/egress tests + 6 token
revocation tests + 16 tenant isolation/audit log tests + 1 graph-export
evidence test + 2 CLI scan-wait tests + 1 additional assertion fix),
all passing against real Postgres, real Redis, and real moto-mocked AWS
— no piece of this was verified against a plain mock alone.

## Real bugs caught this round (not hypothetical)

1. **`httpx.ASGITransport` is async-only** — doesn't implement sync
   `handle_request` or even `close()`. Discovered while trying to test
   the CLI in-process; fixed by running a genuine `uvicorn` server on a
   real loopback socket instead, which turned out to be the more
   faithful test anyway.
2. **Fail-open vs. fail-closed needed real thought, not a default.**
   First draft of token revocation failed *closed* on a Redis outage —
   which would've taken down the *entire* authenticated API on any
   Redis blip, since this check runs on every request (unlike rate
   limiting, which only gates scan-creation). Reconsidered and switched
   to fail-open, matching the existing rate-limiter precedent, with the
   trade-off written down rather than silently chosen.
3. **A test's own comment was wrong**, not the code: an edge-evidence
   test initially asserted evidence that only would have existed if the
   test fixture had gone through `IAMAnalyzer` — but the fixture was
   hand-built test data with empty evidence. Traced it through before
   "fixing" anything; fixed the test's fixture to actually carry
   evidence, not the (already-correct) code.

## What was deliberately NOT built this round

- **Benchmark scenario extension** (adding the remaining 4 synthetic
  scenarios to `benchmarks/`) — started, then abandoned mid-build rather
  than shipped half-tested. The existing 4-scenario harness from the
  earlier delivery is untouched and still valid; this would have been
  additive coverage, not a fix to anything broken.
- **Docker verification** — still requires you to actually run
  `docker compose up --build` and report back. No Docker daemon exists
  in this development environment; every prior audit pass here was by
  careful code review, not execution.
- **Multi-cloud (Azure/GCP)** — explicitly out of scope; would dilute
  focused AWS engine work for surface-level stub providers.

## Merge order

The three deliveries from this round should be merged and committed in
this order (later ones don't strictly depend on earlier ones, but this
matches how they were built and tested):

1. Lambda VPC / EBS / egress correlation
2. JWT revocation / tenant isolation / audit logs (**requires the manual
   `backend/main.py` patch** — see that delivery's patch doc, and run
   `alembic revision --autogenerate` in your own repo for the new
   `account_access` table)
3. Edge-click detail + `cloudpath scan wait`

## Full verification command

After merging all three and applying the `main.py` patch:

```bash
pip install -r requirements.txt
alembic upgrade head
python -m pytest tests/ -v
cd frontend && npm install && npm run build
```

Expect 79+ passing tests (exact count depends on which optional
Postgres/Redis-dependent tests can run in your environment) and a clean
frontend build with zero TypeScript errors.
