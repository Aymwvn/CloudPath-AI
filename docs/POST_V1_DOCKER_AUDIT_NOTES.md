# Post-v1.0 — Docker Audit & Verification (Item #1)

## Honesty up front

I still don't have a Docker daemon in this environment — I cannot
literally run `docker compose up` myself. What I did instead: a careful
line-by-line read of every Docker file, checking for the kinds of bugs
that only show up when you actually build/run a multi-stage,
multi-service Compose setup. This found **two real bugs**, fixed below.
You still need to run the verification steps at the bottom yourself and
tell me what breaks, if anything — I can't close this loop alone.

## Real bugs found and fixed

### 1. No `.dockerignore` — real secret-leak and build-breakage risk

There was no `.dockerignore` file anywhere in the project. Concretely,
this meant:

- `COPY --chown=appuser:appuser . .` in `Dockerfile.backend`/`Dockerfile.worker`
  would copy **`.env` (real secrets), `.git`, `__pycache__`, and
  everything else in the repo** into the image's build context and
  potentially into a layer. A `.env` file with real API keys sitting in
  an image layer is a genuine credential-leak risk if that image is ever
  pushed anywhere.
- `COPY frontend/ ./` in `Dockerfile.frontend`'s build stage would copy
  the **host's `frontend/node_modules`** (if you'd run `npm install`
  locally) into the Linux container, overwriting the container's own
  freshly-`npm ci`'d `node_modules`. This is a well-known, well-
  documented Docker footgun: `node_modules` built on your Windows host
  contains platform-specific native bindings that don't work inside a
  Linux container — this would have caused a real, confusing build/runtime
  failure the first time you actually tried this with `node_modules`
  present locally.

**Fixed**: added `.dockerignore` (repo root) excluding `.env`, `.git`,
`frontend/node_modules/`, `frontend/dist/`, Python cruft, and docs/tests
(not needed inside any runtime image).

### 2. Database migrations were never run anywhere in the documented workflow

The README's Docker instructions were:
```
docker compose up --build
docker compose exec backend python scripts/create_admin.py --username admin
```
**This was missing a step.** `create_admin.py` needs the `users` table
to exist — but nothing in `docker-compose.yml` or either Dockerfile ever
ran `alembic upgrade head`. Following the README exactly, as written,
would have failed on the very first real attempt with a
`relation "users" does not exist` error from Postgres.

**Fixed**: `docker/Dockerfile.backend` now has a proper entrypoint script
(`docker/entrypoint-backend.sh`) that runs `alembic upgrade head` before
starting uvicorn — migrations happen automatically on every container
start, not as a manual step someone has to remember. (Noted limitation:
if this ever scales to multiple backend replicas, concurrent migration
runs on startup are a race condition — fine at this project's current
single-replica scale, worth revisiting with a dedicated one-shot
migration job before scaling horizontally.)

## What I could NOT verify (needs you to actually run it)

- Whether `deploy.resources.limits` is honored by your specific Docker
  Compose version. This requires the modern **Compose V2 CLI**
  (`docker compose`, bundled with current Docker Desktop) — the legacy
  standalone `docker-compose` Python binary ignores `deploy:` entirely
  outside Swarm mode. Check with `docker compose version` — if it prints
  something, you're on V2 and this works; if that command isn't found
  but `docker-compose --version` is, you're on the legacy tool and
  resource limits will be silently ignored (not fatal, just not
  enforced).
- Whether `wget` is actually present in the `nginxinc/nginx-unprivileged:1.27-alpine`
  image for the frontend healthcheck to run. Alpine images typically
  include `wget` via busybox, but "typically" isn't "verified" — if the
  healthcheck shows as failing/unavailable, that's the first thing to check.
- Whether the actual `npm ci` / Python `pip install` steps succeed
  cleanly inside the containers — dependency resolution can behave
  differently in a clean container than on a machine that's accumulated
  a lot of already-cached packages.

## Steps to run yourself (PowerShell)

```powershell
cd "C:\Users\User\Desktop\CloudPathAI"

# 1. Confirm you're on Compose V2
docker compose version

# 2. Set up real secrets
Copy-Item .env.example .env
# edit .env: set POSTGRES_PASSWORD and JWT_SECRET_KEY to real values
# generate JWT_SECRET_KEY with:
python -c "import secrets; print(secrets.token_hex(32))"

# 3. Validate the compose file resolves correctly (catches YAML/interpolation errors)
docker compose config

# 4. Build everything
docker compose build

# 5. Start it
docker compose up -d

# 6. Watch the backend logs — you should see the entrypoint's migration
#    output, then uvicorn starting
docker compose logs -f backend

# 7. Once healthy, check status
docker compose ps

# 8. Bootstrap the first admin (migrations already ran via entrypoint)
docker compose exec backend python scripts/create_admin.py --username admin

# 9. Hit the API
curl http://localhost:8000/health

# 10. Hit the frontend
curl http://localhost/
```

**Report back exactly what happens at each step** — especially step 6
(any migration errors) and step 4 (any build failures) — those are the
two places bugs are most likely to still be hiding, since they're the
parts I could review but not execute.

## Compatibility check

- `docker-compose.yml` itself is unchanged except for what the entrypoint
  fix implies (`Dockerfile.backend`'s `CMD` became `ENTRYPOINT`).
- `.env.example` unchanged.
- No new services, ports, or volumes added.
