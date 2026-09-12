# Contributing to CloudPath AI

This project was built incrementally, phase by phase (see
`docs/ARCHITECTURE.md` Section 42's development rules), with each phase
tested against real infrastructure wherever possible rather than
assuming design-time correctness. New contributions should follow the
same discipline.

## Development setup

```bash
git clone https://github.com/Aymwvn/CloudPath-AI.git
cd CloudPath-AI
pip install -r requirements.txt

# Postgres + Redis for full test coverage (tests skip cleanly without them,
# but you'll want them running for anything touching persistence/queuing)
createdb cloudpath
alembic upgrade head

export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export DATABASE_URL="postgresql+psycopg2://postgres:postgres@localhost:5432/cloudpath"
export TEST_DATABASE_URL="$DATABASE_URL"

python -m pytest tests/ -v
```

Frontend:
```bash
cd frontend && npm install && npm run dev
```

## Ground rules

1. **The deterministic engine (`engine/`) must never depend on AI being
   configured.** `IAMAnalyzer`, `NetworkAnalyzer`, `GraphEngine`,
   `AttackPathEngine`, `RiskEngine`, and `MitreMapper` are all pure,
   testable, no-network-call code. If a change to any of these requires
   an LLM call to work correctly, that's a sign the change belongs in
   `ai/` instead.
2. **AI (`ai/`) only ever receives finalized, already-computed
   `AttackPath`/`RiskAssessment` objects** — never raw AWS data, never
   write access to the graph or the cloud. See `ai/prompt.py`'s
   docstring for why this boundary matters.
3. **Cloud-derived text is untrusted.** Any string that traces back to
   an AWS resource name, tag, or policy document must be treated as
   potentially attacker-controlled when it reaches an AI prompt — wrap
   it in the `<UNTRUSTED_CLOUD_DATA>` pattern established in
   `ai/prompt.py`, don't concatenate it directly into a system prompt.
4. **Read-only cloud access only.** Nothing in `providers/` should ever
   call a mutating AWS API (anything other than `Describe*`/`List*`/
   `Get*`). This is enforced by convention and code review, not by a
   runtime check — be deliberate about this when adding new collectors.
5. **Test against real infrastructure when the change touches it.**
   Several real bugs in this project were only caught by running against
   actual Postgres/Redis rather than trusting mocks (see
   `docs/PHASE9-12_NOTES.md` and `docs/PHASE18_NOTES.md` for two
   documented examples: a primary-key collision that only manifested
   against real Postgres, and a `passlib`/`bcrypt` incompatibility that
   only showed up when actually calling the library). Mocks are fine for
   pure logic; don't rely on them alone for anything that persists data
   or talks to a real service.

## Testing expectations

- New engine logic needs unit tests with hand-constructed fixtures (see
  `tests/test_graph_and_attack_paths.py` for the pattern).
- New API endpoints need integration tests through `TestClient` (see
  `tests/test_backend_api.py`), including an auth-header case and a
  missing/wrong-role case if the endpoint is protected.
- Changes to `engine/iam/` or `engine/network/` should be checked against
  the synthetic scenarios in `tests/test_synthetic_scenarios.py` — if a
  change breaks one of the 8 canonical scenarios, that's worth
  understanding before merging, not silencing.
- Run the full suite before submitting: `python -m pytest tests/ -v`.
  Tests requiring Postgres/Redis are marked to skip cleanly when those
  aren't available, so a passing local run without them is a weaker
  signal than one with them — spin up real Postgres/Redis locally if
  you're touching `backend/db/` or `backend/tasks/`.

## Code style

- Type hints on all function signatures (this codebase targets Python
  3.12+, so modern syntax like `list[str]` and `X | None` is
  preferred over `List[str]`/`Optional[X]`).
- Docstrings that explain **why**, not just what — several files in this
  project (e.g. `engine/risk/engine.py`, `ai/prompt.py`) document a
  design decision or a bug that was found and fixed inline, because that
  context is exactly what the next person touching the file needs and
  won't have otherwise.
- Prefer dataclasses/Pydantic models over raw dicts for anything crossing
  a module boundary — `engine/models.py`'s `Asset`/`Relationship` are the
  canonical example.

## Documenting a phase-sized change

If you're adding something substantial (a new engine, a new API surface,
a new integration), consider writing a short `docs/PHASE<N>_NOTES.md` in
the same style as the existing ones: what was built, any real bugs found
during testing (and how you know they're fixed, not just "probably
fixed"), honest limitations, and a compatibility check against what
already exists. This project's documentation trail has been more useful
for onboarding than the code alone would be.

## Reporting issues

Open a GitHub issue with a clear description and, where possible, a
minimal reproduction. For security-sensitive reports, see
[`SECURITY.md`](SECURITY.md).
