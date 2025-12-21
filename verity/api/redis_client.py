"""Redis client for caching and rate limiting.

Following SOTA 2025 best practices:
- Async redis-py client
- Sliding window rate limiting
- Cache-aside pattern for caching
- Connection management via lifespan
"""

import json
from datetime import datetime
from typing import Any

import redis.asyncio as redis

from verity.config import get_settings

# Get settings
settings = get_settings()

# Redis URL - default to localhost
REDIS_URL = getattr(settings, "redis_url", None) or "redis://localhost:6379/0"


class RedisClient:
    """Async Redis client wrapper for caching and rate limiting."""

    def __init__(self, url: str = REDIS_URL):
        """Initialize Redis client."""
        self.url = url
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis."""
        self._client = redis.from_url(
            self.url,
            encoding="utf-8",
            decode_responses=True,
        )
        # Test connection
        await self._client.ping()

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.close()

    @property
    def client(self) -> redis.Redis:
        """Get Redis client, raise if not connected."""
        if not self._client:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._client

    # ============ Rate Limiting ============

    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int, int]:
        """Check if request is within rate limit using sliding window.

        Args:
            key: Unique identifier (e.g., user_id or IP)
            limit: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (allowed, remaining, reset_time)
        """
        now = datetime.utcnow().timestamp()
        window_start = now - window_seconds
        rate_key = f"ratelimit:{key}"

        # Use Redis pipeline for atomic operations
        async with self.client.pipeline(transaction=True) as pipe:
            # Remove old entries outside window
            await pipe.zremrangebyscore(rate_key, 0, window_start)
            # Count current requests in window
            await pipe.zcard(rate_key)
            # Add current request
            await pipe.zadd(rate_key, {str(now): now})
            # Set expiry on the key
            await pipe.expire(rate_key, window_seconds)

            results = await pipe.execute()

        current_count = results[1]

        if current_count >= limit:
            return False, 0, int(window_seconds)

        remaining = limit - current_count - 1
        return True, remaining, int(window_seconds)

    async def get_usage_count(self, user_id: str, period: str = "month") -> int:
        """Get usage count for a user.

        Args:
            user_id: User identifier
            period: "day", "month", "year"

        Returns:
            Number of attacks used in period
        """
        now = datetime.utcnow()
        if period == "day":
            key = f"usage:{user_id}:{now.strftime('%Y-%m-%d')}"
        elif period == "month":
            key = f"usage:{user_id}:{now.strftime('%Y-%m')}"
        else:
            key = f"usage:{user_id}:{now.year}"

        count = await self.client.get(key)
        return int(count) if count else 0

    async def increment_usage(self, user_id: str) -> int:
        """Increment usage counter for user.

        Returns:
            New usage count
        """
        now = datetime.utcnow()
        key = f"usage:{user_id}:{now.strftime('%Y-%m')}"

        count = await self.client.incr(key)

        # Set expiry to end of month + buffer
        days_remaining = 32 - now.day
        await self.client.expire(key, days_remaining * 24 * 3600)

        return count

    # ============ Caching ============

    async def cache_get(self, key: str) -> Any | None:
        """Get value from cache.

        Returns deserialized value or None if not found.
        """
        value = await self.client.get(f"cache:{key}")
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None

    async def cache_set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 3600,
    ) -> None:
        """Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl_seconds: Time to live in seconds
        """
        if isinstance(value, (dict, list)):
            value = json.dumps(value)

        await self.client.setex(f"cache:{key}", ttl_seconds, value)

    async def cache_delete(self, key: str) -> None:
        """Delete value from cache."""
        await self.client.delete(f"cache:{key}")

    async def cache_invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all cache keys matching pattern.

        Returns:
            Number of keys deleted
        """
        keys = []
        async for key in self.client.scan_iter(match=f"cache:{pattern}"):
            keys.append(key)

        if keys:
            return await self.client.delete(*keys)
        return 0

    # ============ Session Storage ============

    async def store_session(
        self,
        token: str,
        user_id: str,
        ttl_seconds: int = 900,  # 15 minutes
    ) -> None:
        """Store JWT token session."""
        await self.client.setex(f"session:{token}", ttl_seconds, user_id)

    async def get_session(self, token: str) -> str | None:
        """Get user_id from session token."""
        return await self.client.get(f"session:{token}")

    async def delete_session(self, token: str) -> None:
        """Delete session (logout)."""
        await self.client.delete(f"session:{token}")


# Global Redis client instance
redis_client = RedisClient()


# FastAPI dependency
async def get_redis() -> RedisClient:
    """Get Redis client for FastAPI dependency injection."""
    return redis_client
