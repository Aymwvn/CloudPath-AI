# Backend Patch: JWT Revocation + Audit Logs Endpoint + Tenant Isolation

Same discipline as the graph-visualization patch: your `backend/main.py`
is too large and security-critical to safely reconstruct from memory, so
this is a precise patch to apply by hand, not a file replacement.

## 1. Replace `backend/auth.py` with the version in this delivery

The only change: `create_access_token()` now includes a `jti` (unique
token id) claim. This is what makes revocation possible without storing
full tokens anywhere.

## 2. Add three new files (copy directly, no changes needed)

- `backend/token_revocation.py` — Redis-backed blocklist
- `backend/tenant_scope.py` — account-access checks
- `backend/audit_log_query.py` — audit log read queries

## 3. Add `AccountAccessModel` to `backend/db/models.py`

Append this class (it's additive — doesn't touch any existing model):

```python
class AccountAccessModel(Base):
    """Tenant isolation. Grants a specific user access to scans/data
    belonging to a specific cloud account (by external account id).
    Admins bypass this check entirely — this table only governs
    non-admin visibility."""

    __tablename__ = "account_access"

    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String, nullable=False)
    account_external_id = Column(String, nullable=False)
    granted_by = Column(String, nullable=False)
    granted_at = Column(DateTime, default=_now)
```

Then generate the real migration **in your own repo**, where the actual
migration history lives (I don't have it in this session, and guessing
at a `down_revision` risks corrupting your chain):

```bash
alembic revision --autogenerate -m "add account_access table"
alembic upgrade head
```

## 4. Patch `get_current_user` to check revocation

Find your existing `get_current_user` function and add the revocation
check right after decoding the token:

```python
def get_current_user(token: str | None = Depends(oauth2_scheme)) -> CurrentUser:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise unauthorized
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")
        if not username or not role:
            raise unauthorized

        # NEW: reject a revoked token even if its signature/expiry are valid
        from backend.token_revocation import is_revoked
        if jti and is_revoked(jti):
            raise unauthorized

        return CurrentUser(username=username, role=role)
    except JWTError:
        raise unauthorized from None
```

Store the decoded `jti` on `CurrentUser` too (add a field) so the new
`/auth/logout` endpoint below can revoke the *current* token:

```python
class CurrentUser:
    def __init__(self, username: str, role: str, jti: str | None = None):
        self.username = username
        self.role = role
        self.jti = jti
```//and pass `jti=jti` in the `return CurrentUser(...)` line above.

## 5. Add `POST /api/v1/auth/logout`

```python
@app.post("/api/v1/auth/logout")
def logout(user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    from datetime import datetime, timedelta, timezone
    from backend.token_revocation import revoke_token

    if user.jti:
        # token's own remaining lifetime — matches ACCESS_TOKEN_EXPIRE_MINUTES
        # in backend/auth.py; revoke_token() only needs an upper bound,
        # not the exact original expiry, so this is safely approximate
        revoke_token(user.jti, datetime.now(timezone.utc) + timedelta(minutes=30))
    write_audit_log(db, actor=user.username, action="auth.logout")
    return {"status": "logged out"}
```

## 6. Add `GET /api/v1/audit-logs` (admin-only)

```python
@app.get("/api/v1/audit-logs")
def get_audit_logs(
    limit: int = 50, offset: int = 0, actor: str | None = None, action: str | None = None,
    admin: CurrentUser = Depends(require_role("admin")), db: Session = Depends(get_db),
) -> list[dict]:
    from backend.audit_log_query import list_audit_logs
    return list_audit_logs(db, limit=limit, offset=offset, actor=actor, action=action)
```

## 7. Add account-access management endpoints (admin-only)

```python
@app.post("/api/v1/accounts/{account_external_id}/access")
def grant_access(
    account_external_id: str, username: str,
    admin: CurrentUser = Depends(require_role("admin")), db: Session = Depends(get_db),
) -> dict:
    from backend.tenant_scope import grant_account_access
    grant_account_access(db, username=username, account_external_id=account_external_id, granted_by=admin.username)
    write_audit_log(db, actor=admin.username, action="account_access.grant", target=account_external_id, details={"username": username})
    return {"status": "granted"}


@app.delete("/api/v1/accounts/{account_external_id}/access")
def revoke_access(
    account_external_id: str, username: str,
    admin: CurrentUser = Depends(require_role("admin")), db: Session = Depends(get_db),
) -> dict:
    from backend.tenant_scope import revoke_account_access
    revoke_account_access(db, username=username, account_external_id=account_external_id)
    write_audit_log(db, actor=admin.username, action="account_access.revoke", target=account_external_id, details={"username": username})
    return {"status": "revoked"}
```

## 8. Enforce tenant scoping on the Postgres-backed read paths

**Important scoping note**: tenant isolation only meaningfully applies
to **Postgres-persisted (async) scans** — the synchronous `POST
/api/v1/scans` path (Phase 8 behavior, in-memory only) never creates a
`ScanJobModel` row at all, so there's no account-ownership record to
check for it. That endpoint is already documented as a "local/demo"
feature, not the production path — this patch doesn't change that, it
just doesn't pretend to scope something that has no owner to scope
against.

In `get_scan`'s Postgres fallback branch, add the access check before
returning:

```python
if pg is not None:
    try:
        record = pg.get(scan_id)
        if record:
            from backend.db.session import SessionLocal
            from backend.tenant_scope import user_can_access_account
            session = SessionLocal()
            try:
                if not user_can_access_account(session, user.username, user.role, record.scan_result.account_id):
                    raise HTTPException(status_code=404, detail="Scan not found")  # 404, not 403 — don't confirm existence
            finally:
                session.close()
    except Exception:
        record = None
```

(You'll need to add `user: CurrentUser = Depends(get_current_user)` to
`get_scan`'s signature if it doesn't already require auth on that
branch — check your current implementation.)

The same pattern (look up the scan's `account_external_id`, check
`user_can_access_account`, 404 instead of 403 if denied) should be
applied to:
- `analyze_attack_path` / `get_attack_path_analysis` / `get_mitre_mappings`
  — look up the attack path's `scan_job_id` → that job's
  `account_external_id`
- Any future endpoint that reads Postgres-persisted scan data

**Why 404 instead of 403** for a denied account: returning 403 confirms
"this scan_id exists, you just can't see it" — which leaks information
to an unauthorized user about what exists in the system. 404 ("not
found") reveals nothing either way, matching how `get_scan` already
handles a genuinely-nonexistent scan_id.

## Verify

```bash
python -m pytest tests/test_token_revocation.py tests/test_tenant_isolation_and_audit_logs.py -v
```

23 tests total, all against real Redis/Postgres, none mocked.
