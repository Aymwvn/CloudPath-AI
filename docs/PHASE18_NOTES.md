# Phase 18 — Security Hardening Notes

## What was built

**Authentication & RBAC** — `backend/auth.py`. JWT-based (stateless
access tokens, 30-minute expiry), passwords hashed with `bcrypt`
directly. Three roles in a hierarchy: `viewer < analyst < admin`.
`Depends(get_current_user)` requires any valid token;
`Depends(require_role("analyst"))` requires that role or higher.
`POST /api/v1/auth/login` issues tokens; `POST /api/v1/auth/register`
is admin-only (no public self-registration into a security tool).
`scripts/create_admin.py` bootstraps the first admin user directly
against the database, since nothing can call the admin-only register
endpoint before an admin exists.

**Applied to every endpoint:**
- `viewer` or higher: all `GET` endpoints (read scan data)
- `analyst` or higher: `POST /scans`, `/scans/async`, `/simulation`,
  `/attack-paths/{id}/analyze`
- `admin` only: `POST /auth/register`
- Unauthenticated: `/health` (standard liveness-probe practice), `/auth/login`

**Rate limiting** — `backend/rate_limit.py`. Redis-backed fixed-window
counter, 10 scans/hour/user by default, applied to the scan-triggering
endpoints. Fails open (allows the request) if Redis itself is
unreachable — a deliberate availability-over-strictness trade-off,
documented in the code rather than silent.

**Audit logging** — new `AuditLogModel` table, written on login
success/failure, scan creation (sync and async), user creation, and AI
analysis runs. New Alembic migration applied and verified against real
Postgres.

**Docker hardening** — `docker/Dockerfile.backend`, `Dockerfile.worker`,
`Dockerfile.frontend`, `docker-compose.yml`, `.env.example`. Non-root
users in every container, multi-stage frontend build (no Node toolchain
in the final image), resource limits (`deploy.resources.limits`) on
every service, and network isolation — Postgres and Redis sit on an
`internal: true` Docker network with **no host port mapping at all**,
reachable only by the backend/worker containers.

## Bugs found while testing (both real, not test artifacts)

1. **`passlib` + current `bcrypt` are incompatible.** Verified directly
   before writing any auth code around it: `passlib`'s bcrypt backend
   assumes a `bcrypt.__about__.__version__` attribute that newer
   `bcrypt` releases removed, causing every hash/verify call to crash.
   Used `bcrypt` directly instead of `passlib` — simpler anyway, one
   less dependency, and confirmed working before building on top of it.
2. **Rate-limiting introduced a real test-isolation gap.** Tests that
   hit the scan-creation endpoint originally used a fixed username
   (`"test-analyst"`). Since the rate limiter tracks usage in real
   Redis, re-running the test suite repeatedly within the same hour
   window (which happened naturally during this session) eventually
   exhausted that username's 10-scans/hour budget and made unrelated
   tests fail with confusing 404s — the scan silently failed with 429,
   and downstream assertions about the (nonexistent) scan result broke
   with misleading errors. **Fixed** by giving each test-process run a
   unique username (`test-analyst-{random suffix}`), and **verified the
   fix** by running the affected test files three times in a row
   (something the bug would have broken by the 2nd or 3rd run) — all
   green each time.

## Honest limitations (stated plainly)

1. **Docker files are UNTESTED BY EXECUTION.** No Docker daemon is
   available in the environment this was built in — I validated the
   `docker-compose.yml` YAML syntax parses correctly and reasoned
   carefully about each Dockerfile, but **none of these have actually
   been built or run**. This is different from everything else in this
   project, which was verified against real Postgres/Redis/AWS-mocks.
   **Run `docker compose up --build` yourself and confirm it works
   before trusting it in your report** — don't take my word for this
   one specific piece.
2. **No tenant/multi-account isolation enforcement** — RBAC controls
   *what actions* a user can take, not *which cloud accounts' data* they
   can see. Every authenticated user can currently read every scan's
   data regardless of which `cloud_accounts` row it belongs to. Real
   tenant isolation (Section 31's "Tenant isolation") needs the
   `cloud_accounts` → scan ownership relationship enforced at the query
   level, which doesn't exist yet.
3. **JWT tokens can't be revoked before they expire.** 30-minute expiry
   limits the blast radius of a leaked token, but there's no
   token-blocklist/refresh-token rotation — logging out client-side just
   discards the token locally, it's still valid server-side until it
   expires naturally.
4. **`OAuth2PasswordRequestForm` login uses form-encoded POST**, not
   JSON — this is FastAPI/OAuth2's standard pattern (and what Swagger
   UI's built-in "Authorize" button expects), but it's worth knowing if
   you're calling `/auth/login` from the frontend, which needs
   `application/x-www-form-urlencoded`, not `JSON.stringify`.
5. **Secrets in `.env.example` are placeholder strings**, obviously —
   but worth saying explicitly: never commit a real `.env` file, and
   generate a real `JWT_SECRET_KEY` per-deployment
   (`python -c "import secrets; print(secrets.token_hex(32))"`), never
   reuse the one from this file or from tests.

## How to run it

```bash
pip install -r requirements.txt
alembic upgrade head    # picks up users + audit_logs tables

export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python scripts/create_admin.py --username admin   # prompts for password

uvicorn backend.main:app --reload
# then POST /api/v1/auth/login with form data username=admin&password=...
# to get a token, use it as "Authorization: Bearer <token>" on everything else

python -m pytest tests/ -v   # 113 tests, all passing as of this phase
```

## Compatibility check

- All existing endpoints keep their exact same request/response shapes
  — only new required auth headers were added, no schema changes.
- Phase 8/10/13/15 test files were updated (not silently left broken) to
  send auth headers — every existing assertion still holds, just now
  behind a valid token.
- The rate-limit fix required editing 2 test files; documented above
  rather than glossed over as a routine change.
