"""
backend/tenant_scope.py — Post-v1.0 tenant isolation.

Before this, RBAC controlled *what actions* a role could take (viewer
can read, analyst can scan, admin can manage users) but not *which cloud
accounts' data* a user could see — any authenticated user could read any
scan's results regardless of which AWS account it came from. This was
the single most-flagged gap across every prior phase's notes.

Design: admins see everything (matches their existing role semantics
elsewhere in the app — admin is already the "can do anything" tier).
Non-admins must be explicitly granted access to a specific cloud account
(by its external account id, e.g. the AWS account number) via
AccountAccessModel. No grant = no visibility into that account's scans,
full stop — this is a default-deny model, not default-allow.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.db import models


def grant_account_access(session: Session, username: str, account_external_id: str, granted_by: str) -> None:
    existing = (
        session.query(models.AccountAccessModel)
        .filter_by(username=username, account_external_id=account_external_id)
        .one_or_none()
    )
    if existing:
        return  # already granted — idempotent, not an error
    session.add(
        models.AccountAccessModel(username=username, account_external_id=account_external_id, granted_by=granted_by)
    )
    session.commit()


def revoke_account_access(session: Session, username: str, account_external_id: str) -> None:
    session.query(models.AccountAccessModel).filter_by(
        username=username, account_external_id=account_external_id
    ).delete()
    session.commit()


def list_accessible_account_ids(session: Session, username: str, role: str) -> list[str] | None:
    """Returns the list of AWS account ids this user can see, or None to
    mean "all accounts" (admins only) — callers must check for None
    explicitly rather than treating it as an empty-access list."""
    if role == "admin":
        return None
    rows = session.query(models.AccountAccessModel).filter_by(username=username).all()
    return [r.account_external_id for r in rows]


def user_can_access_account(session: Session, username: str, role: str, account_external_id: str) -> bool:
    if role == "admin":
        return True
    return (
        session.query(models.AccountAccessModel)
        .filter_by(username=username, account_external_id=account_external_id)
        .one_or_none()
        is not None
    )


def user_can_access_scan(session: Session, username: str, role: str, scan_id: str) -> bool:
    """Convenience wrapper: looks up which AWS account a scan belongs to,
    then checks access to that account. Returns False (not an exception)
    for an unknown scan_id — the caller should treat that as a 404, not
    distinguish it from an access-denied case (returning 404 either way
    also avoids leaking whether a given scan_id exists at all to a user
    who isn't authorized to see it)."""
    job = session.get(models.ScanJobModel, scan_id)
    if not job:
        return False
    return user_can_access_account(session, username, role, job.account_external_id)
