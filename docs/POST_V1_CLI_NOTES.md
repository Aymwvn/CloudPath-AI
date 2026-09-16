# Post-v1.0 — The Real `cloudpath` CLI (Item #2)

## What was built

`cli/` package + `pyproject.toml` (adds a `cloudpath` console-script
entry point via `pip install -e .`). This replaces
`scripts/run_scan_demo.py`'s role as the project's only CLI-like
interface with the real thing ARCHITECTURE.md Section 35 described.

**Design choice: the CLI is an API client, not a second engine
implementation.** It talks to your running FastAPI backend over HTTP
with a saved login session (`~/.cloudpath/config.json`, same pattern as
`aws configure`/`gh auth login`) — it does not re-run
`ScanService`/`GraphEngine`/etc. locally. Every `cli/client.py` method
maps to exactly one existing backend endpoint. This matters: it means
the CLI automatically respects your RBAC roles, rate limiting, and
audit logging, since it's just another authenticated client of the same
API your dashboard uses — not a bypass.

**Commands implemented:**
```
cloudpath login --url <url>              # authenticate, save session
cloudpath logout
cloudpath whoami
cloudpath status [--url <url>]           # health check, no auth needed

cloudpath scan aws [--region R] [--async] [--crown-jewel ID...]
cloudpath scan status <scan_id>

cloudpath assets list [--scan-id ID] [--type TYPE] [--json]

cloudpath paths list [--scan-id ID] [--min-severity S] [--json]
cloudpath paths show <attack_path_id>     # MITRE + existing AI analysis
cloudpath paths analyze <attack_path_id>  # trigger AI analysis

cloudpath simulate --remove SOURCE:TARGET:EDGE_TYPE [--scan-id ID]

cloudpath report [--format json|markdown] [--output FILE] [--scan-id ID]
```

## A real, fundamental testing bug found and fixed along the way

My first approach to testing this end-to-end used `httpx.ASGITransport`
to run the CLI against an in-process FastAPI app without a real network
socket — this is a commonly-recommended pattern for testing ASGI apps.
**It doesn't work for this CLI, and the reason is worth understanding:**
`ASGITransport` only implements `handle_async_request` — it has no sync
`handle_request` and no `close()` method at all (confirmed by inspecting
the object directly, not by reading docs and assuming). It's built for
`httpx.AsyncClient`. This CLI's `CloudPathClient` uses a synchronous
`httpx.Client` throughout (Click commands are synchronous), so pairing
it with `ASGITransport` fails with a confusing
`AttributeError: 'ASGITransport' object has no attribute 'close'`
buried inside otherwise-successful-looking test output.

**The fix**: run a genuine `uvicorn` server on a real loopback TCP port
in a background thread, with proper readiness polling before tests
start, and point the CLI at real `http://127.0.0.1:<port>` over real
HTTP. This isn't a workaround — it's arguably a *more* faithful test of
real CLI usage than the in-process shortcut would have been, since the
production CLI always talks to a real server over real HTTP anyway.

**Verified twice, two different ways:**
1. `tests/test_cli.py` — 19 tests, pytest-managed real server + Click's
   `CliRunner` (in-process command invocation, real HTTP underneath).
2. A separate manual smoke test using `subprocess.run()` to call the
   actual installed `cloudpath` binary (not through pytest's fixtures at
   all) against a manually-started real server — confirmed `status`,
   `login`, and `whoami` all work correctly from a genuinely separate
   process, which is the closest thing to "a user typing this at their
   own terminal" achievable in this environment.

## `tests/cli_test_server.py` — a new, real (not mocked) test fixture

This is a minimal FastAPI app implementing real `ScanService`, real JWT
auth (reusing `backend/auth.py`'s actual signing/verification), and real
`graph_export` logic — but with an in-memory user dict instead of
Postgres, so CLI tests run fully offline and fast. This is a deliberate,
documented scope reduction for **testing purposes only** — it's not a
suggestion that the real backend should skip Postgres. It's a genuinely
useful test fixture going forward for anyone extending the CLI.

## Known limitations (intentional, deferred)

1. **`cloudpath report` aggregates client-side, not server-side** —
   there's no `/api/v1/reports` endpoint (ARCHITECTURE.md Section 34's
   server-side report generation, including PDF export, isn't built).
   The CLI's `report` command is a legitimate, documented stand-in that
   fetches statistics + attack paths and formats them locally — not a
   claim that server-side reporting exists.
2. **No `crown-jewels`, `paths show PATH-001` exact-ARCHITECTURE-syntax
   parity** — the original design's example CLI syntax
   (`cloudpath paths show PATH-001`) is close but not identical to what
   was built (`cloudpath paths show <real-uuid>`, since path ids are
   real database UUIDs, not friendly sequential labels like "PATH-001").
   A friendly-alias layer (mapping "PATH-001" to a real UUID) wasn't
   built — this is a minor UX gap, not a missing capability.
3. **`--async` scans require checking status separately** — there's no
   `cloudpath scan wait <scan_id>` that blocks and polls until
   completion; you currently run `scan aws --async` then manually run
   `scan status <id>` repeatedly. A polling `wait` subcommand is a small,
   natural follow-up.
4. **No shell completion configured** — Click supports this
   (`_CLOUDPATH_COMPLETE=bash_source cloudpath` etc.) but wasn't wired
   into an installer step.

## How to install and use it

```bash
pip install -e .          # installs the `cloudpath` command
cloudpath --help

cloudpath login --url http://localhost:8000 --username admin
cloudpath scan aws --region us-east-1
cloudpath assets list --type EC2
cloudpath paths list --min-severity HIGH
cloudpath report --format markdown --output report.md
```

## Compatibility check

- No changes to `backend/main.py` or any existing endpoint — the CLI is
  purely an additive client.
- `pyproject.toml` is new; doesn't replace or conflict with
  `requirements.txt` (which still governs the actual app's runtime
  dependencies). Add `click>=8.1` and `rich>=13.0` to `requirements.txt`
  too if you want `pip install -r requirements.txt` alone to cover CLI
  dependencies without also running `pip install -e .`.
- 47/47 tests pass project-wide after this addition.
