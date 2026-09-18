"""
backend/audit_log_query.py — read access to AuditLogModel for the new
GET /api/v1/audit-logs endpoint. Audit data has existed in the database
since Phase 18 but was never queryable via the API until now.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.db import models


def list_audit_logs(
    session: Session,
    limit: int = 50,
    offset: int = 0,
    actor: str | None = None,
    action: str | None = None,
) -> list[dict]:
    query = session.query(models.AuditLogModel).order_by(models.AuditLogModel.timestamp.desc())
    if actor:
        query = query.filter(models.AuditLogModel.actor == actor)
    if action:
        query = query.filter(models.AuditLogModel.action == action)

    rows = query.offset(offset).limit(min(limit, 500)).all()  # hard ceiling — never let a caller request unbounded rows

    return [
        {
            "id": r.id,
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "details": r.details,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in rows
    ]
