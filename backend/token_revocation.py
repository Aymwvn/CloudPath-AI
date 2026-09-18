"""
backend/token_revocation.py — Redis-backed JWT revocation.

Access tokens are short-lived (30 min) but can't be invalidated before
their natural expiry by default — logging out client-side just discards
the token locally; the server still honors it. This closes that gap:
`POST /api/v1/auth/logout` calls `revoke_token()` with the current
token's `jti` claim, and `get_current_user` checks `is_revoked()` after
decoding a token, before trusting it.

Uses a TTL exactly matching the token's remaining lifetime — a revoked
token's blocklist entry expires itself the moment the token would have
expired anyway, so this Redis key never accumulates unboundedly.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


def _blocklist_key(jti: str) -> str:
    return f"revoked_token:{jti}"


def revoke_token(jti: str, expires_at: datetime, client: redis.Redis | None = None) -> None:
    """Blocklists a token by its jti until `expires_at` (the token's own
    `exp` claim) — after that point the token would be rejected as
    expired anyway, so there's no need to remember it any longer.

    If Redis is unreachable, this raises — logout should tell the user
    clearly that it failed rather than silently pretending it worked
    (matches the honesty principle used throughout: never claim
    something succeeded that didn't)."""
    r = client or get_redis_client()
    ttl_seconds = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
    r.set(_blocklist_key(jti), "1", ex=ttl_seconds)


def is_revoked(jti: str, client: redis.Redis | None = None) -> bool:
    """Checks whether a token's jti is blocklisted.

    Fails OPEN (returns False = "not revoked") if Redis is unreachable —
    deliberately, not by oversight. Unlike rate limiting, this check
    runs on EVERY authenticated request, not just scan-creation; failing
    closed here would take down the entire authenticated API surface on
    any Redis blip, to protect against a narrow risk window (revocation
    only matters for the remainder of a token's already-short 30-minute
    lifetime — the token's signature and expiry, unaffected by Redis
    availability, remain the primary security boundary either way).
    A deployment wanting stricter behavior can catch redis.RedisError
    here and fail closed instead; this default favors availability."""
    r = client or get_redis_client()
    try:
        return r.exists(_blocklist_key(jti)) > 0
    except redis.RedisError:
        return False
