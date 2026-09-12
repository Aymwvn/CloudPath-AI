"""
Phase 18 — authentication and RBAC.

ARCHITECTURE.md Section 31: "Authentication, RBAC, API authentication...
Never store AWS secret keys in plaintext... short-lived credentials."

JWT-based auth (short-lived access tokens, no server-side session state
to manage). Passwords hashed with `bcrypt` directly — NOT `passlib`,
which has a confirmed incompatibility with current `bcrypt` versions
(passlib 1.7.4 assumes a `bcrypt.__about__.__version__` attribute that
was removed; verified by testing directly rather than assuming
compatibility, since this exact combination is a live footgun as of this
writing).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.db import models
from backend.db.session import SessionLocal

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def _get_secret_key() -> str:
    """Fails loudly rather than falling back to a hardcoded default —
    a default secret key would make every deployment's tokens forgeable
    by anyone who's read this file on GitHub."""
    if not SECRET_KEY:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not set. Generate one with "
            "`python -c \"import secrets; print(secrets.token_hex(32))\"` and set it "
            "before starting the API — auth cannot run with a default/guessable key."
        )
    return SECRET_KEY


def hash_password(password: str) -> str:
    # bcrypt has a hard 72-byte input limit — truncate defensively rather
    # than letting a long password silently raise inside bcrypt itself
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))


def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raises JWTError on an invalid/expired/tampered token — callers
    (get_current_user) are responsible for turning that into a 401."""
    return jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])


def get_db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class CurrentUser:
    def __init__(self, username: str, role: str):
        self.username = username
        self.role = role


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
        if not username or not role:
            raise unauthorized
        return CurrentUser(username=username, role=role)
    except JWTError:
        raise unauthorized from None


def require_role(minimum_role: str):
    """FastAPI dependency factory — e.g. Depends(require_role("analyst"))
    lets analyst AND admin through, blocks viewer. Role check is by
    hierarchy level, not exact match, matching how RBAC is described in
    ARCHITECTURE.md Section 23 (viewer/analyst/admin as an ordered set of
    permissions, not independent flags)."""

    def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if ROLE_HIERARCHY.get(current_user.role, -1) < ROLE_HIERARCHY.get(minimum_role, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role}' role or higher; you have '{current_user.role}'",
            )
        return current_user

    return dependency


def write_audit_log(session: Session, actor: str, action: str, target: str | None = None, details: dict | None = None) -> None:
    session.add(models.AuditLogModel(actor=actor, action=action, target=target, details=details or {}))
    session.commit()
