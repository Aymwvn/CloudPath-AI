from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}


def _get_secret_key() -> str:
    if not SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY environment variable is not set.")
    return SECRET_KEY


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))


def create_access_token(username: str, role: str) -> str:
    # `jti` (JWT ID) — a unique identifier per issued token, not derived
    # from its contents. This is what makes revocation possible without
    # storing full tokens anywhere: logging out just needs to blocklist
    # this one short id in Redis until the token's natural expiry, not
    # the token itself (ARCHITECTURE.md Section 18/31 — no plaintext
    # secrets stored longer than necessary).
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
