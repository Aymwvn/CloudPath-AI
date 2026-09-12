"""
Phase 18 — rate limiting.

Fixed-window counter backed by Redis (already a dependency since Phase
10's Celery broker) — matches ARCHITECTURE.md Section 31's "Rate
limiting" requirement. Keyed by authenticated username (falls back to
"anonymous" only where auth itself is optional, but every endpoint this
is applied to already requires auth via backend/auth.py, so in practice
the key is always a real username).
"""
from __future__ import annotations

import os
import time

import redis
from fastapi import Depends, HTTPException, Request, status

from backend.auth import CurrentUser, get_current_user

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


class RateLimiter:
    """Fixed-window limiter: at most `limit` calls per `window_seconds`
    per key. Fixed-window (not sliding/token-bucket) is a deliberate
    simplicity choice for the MVP — it allows brief bursts right at
    window boundaries, which is an accepted, documented trade-off, not
    an oversight; a sliding-window/token-bucket upgrade is a drop-in
    replacement for this class later if burst behavior needs tightening.
    """

    def __init__(self, limit: int, window_seconds: int, client: redis.Redis | None = None):
        self.limit = limit
        self.window_seconds = window_seconds
        self._client = client

    def _get_client(self) -> redis.Redis:
        return self._client or get_redis_client()

    def check(self, key: str) -> None:
        client = self._get_client()
        window = int(time.time()) // self.window_seconds
        redis_key = f"ratelimit:{key}:{window}"

        try:
            count = client.incr(redis_key)
            if count == 1:
                client.expire(redis_key, self.window_seconds)
        except redis.RedisError:
            # Redis unreachable — fail OPEN (allow the request) rather
            # than taking the whole API down over a rate-limiter outage.
            # This is a deliberate availability-over-strictness trade-off,
            # documented here rather than silently swallowed.
            return

        if count > self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {self.limit} requests per {self.window_seconds}s",
            )


def scan_rate_limiter(limit: int = 10, window_seconds: int = 3600):
    """Dependency factory for scan-triggering endpoints — defaults to 10
    scans/hour per user, generous enough for legitimate use but bounds
    the blast radius of a compromised token or a buggy client stuck in
    a retry loop."""
    limiter = RateLimiter(limit=limit, window_seconds=window_seconds)

    def dependency(current_user: CurrentUser = Depends(get_current_user)) -> None:
        limiter.check(current_user.username)

    return dependency
