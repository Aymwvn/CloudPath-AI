# Security Model

CloudPath AI is a **defensive** cloud-security analysis platform. It never
exploits discovered attack paths, never modifies scanned cloud infrastructure,
and requires only read-only AWS permissions. This document describes the
platform's own security posture — the threat model for CloudPath AI itself,
not the AWS security findings it produces.

## Threat model

**In scope — threats to the CloudPath AI platform:**

- **Prompt injection via cloud resource metadata.** Resource names, tags,
  and policy documents are attacker-influenceable (anyone who can name an
  S3 bucket can put arbitrary text in the prompt an AI model eventually
  sees). Mitigated by wrapping all cloud-derived text in explicit
  `<UNTRUSTED_CLOUD_DATA>` delimiters with an instruction to treat that
  block as data, never as commands — see `ai/prompt.py` and
  `tests/test_ai_layer.py`'s injection-defense test, which plants an
  injection attempt in fake evidence and confirms it stays inside the
  delimited block.
- **Credential leakage of the scanning role.** Mitigated by documenting
  (and enforcing via the least-privilege IAM policy in `docs/ARCHITECTURE.md`
  Section 10) that only read-only permissions are ever requested, and by
  never persisting AWS credentials in the database — `boto3.Session()` is
  constructed from whatever the environment/instance role provides at
  scan time and never written to disk.
- **Unauthorized API access.** Mitigated by JWT authentication and RBAC
  (see below) — every endpoint except `/health` and `/auth/login`
  requires a valid bearer token.
- **Excessive resource consumption / abuse.** Mitigated by Redis-backed
  rate limiting on scan-triggering endpoints (10/hour/user by default).
- **Cross-tenant data leakage.** **Not yet fully mitigated** — see Known
  Gaps below. This is a real, open item, not something papered over.

**Explicitly out of scope:**

- Exploiting any attack path CloudPath AI discovers.
- Modifying, deleting, or otherwise mutating scanned cloud resources.
- Offensive tooling of any kind. This is not a penetration-testing
  execution platform — it's an analysis and reporting platform.

## Authentication & authorization

- **JWT bearer tokens**, 30-minute expiry, HS256-signed with a secret key
  that must be explicitly set via `JWT_SECRET_KEY` — the API refuses to
  start auth-dependent code paths with no key configured rather than
  falling back to a default (a default would make every deployment's
  tokens forgeable by anyone who's read this repository).
- **Three roles, hierarchical:** `viewer` < `analyst` < `admin`.
  - `viewer`: read scan results, assets, attack paths, statistics.
  - `analyst`: everything a viewer can do, plus trigger scans, run
    what-if simulations, and request AI analysis.
  - `admin`: everything an analyst can do, plus create new user accounts.
- **No public self-registration.** `POST /api/v1/auth/register` is
  admin-only by design — this is an internal security tool, not a
  consumer product; letting anyone create an account with a chosen role
  would defeat the purpose of RBAC. The very first admin account is
  created via `scripts/create_admin.py`, run directly against the
  database, not through the API.
- **Passwords** are hashed with `bcrypt` (never `passlib` — see
  `docs/PHASE18_NOTES.md` for a documented, verified incompatibility
  between `passlib` and current `bcrypt` releases). Never logged, never
  stored in plaintext anywhere, never included in audit log details.

## Rate limiting

Redis-backed fixed-window counter, applied per authenticated username
(not per-IP, since every rate-limited endpoint already requires auth).
Default: 10 scans/hour/user. **Fails open** if Redis itself is
unreachable — an explicit availability-over-strictness trade-off: a
Redis outage degrades to "no rate limiting" rather than "API completely
unusable." This is a deliberate choice, documented in
`backend/rate_limit.py`, not an oversight.

## Audit logging

Every login (success and failure), scan creation (sync and async), user
creation, and AI analysis run is recorded in the `audit_logs` table with
the acting username, action, target, and a timestamp. Audit logs are
currently readable only via direct database access — no
`GET /api/v1/audit-logs` endpoint exists yet (tracked as a gap below).

## Secrets handling

- AWS credentials: never persisted; sourced from the environment/IAM
  role at scan time only.
- `JWT_SECRET_KEY`: must be set via environment variable; no default.
- AI provider API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`): read
  from environment variables only, never logged, never stored in the
  database.
- Database password: set via `POSTGRES_PASSWORD` in `.env` (see
  `.env.example`) — never committed, never hardcoded.

## Known gaps (stated plainly, not hidden)

These are real, current limitations — not aspirational "future work" that
sounds better than it is:

1. **No tenant/multi-account isolation enforcement.** RBAC controls
   *what actions* a role can take, not *which cloud accounts' scan data*
   a user can see. Any authenticated user can currently read any scan's
   results regardless of which AWS account it came from. If you're
   scanning multiple AWS accounts belonging to different customers or
   teams, do not treat the current RBAC as isolating their data from
   each other.
2. **No JWT revocation.** A leaked token remains valid until its
   30-minute expiry — there's no server-side blocklist or refresh-token
   rotation to invalidate it earlier.
3. **Docker hardening is unverified by execution** — written to best
   practices (non-root users, resource limits, network isolation) but
   never actually built/run in this project's own development
   environment (no Docker daemon was available). Verify it yourself
   before relying on it in production.
4. **No `GET /api/v1/audit-logs` endpoint** — audit data exists in the
   database but isn't exposed via the API yet.
5. **Rate limiting is per-user, not per-IP** — a single compromised
   token can still be used from many IPs simultaneously up to that
   user's limit; there's no additional IP-based throttling layer.
6. **No dependency vulnerability scanning configured** — `requirements.txt`
   and `frontend/package-lock.json` pin versions but nothing in CI
   currently checks them against known CVEs (e.g. `pip-audit`,
   `npm audit`, Dependabot). Worth adding.

## Reporting a vulnerability

This is an open-source educational/portfolio project without a formal
security response team. If you find a vulnerability, please open a
GitHub issue with a clear description and reproduction steps. For
anything sensitive enough that public disclosure feels premature, note
that in the issue and a fix will be prioritized before further public
discussion of exploitation details.
