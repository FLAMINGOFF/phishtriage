"""Token-bucket rate limit and daily budget for VirusTotal, shared by all workers via Redis.

The bucket holds at most one token and gains one every ``60 / rate_per_minute`` seconds
(15 s for the free API's 4 requests/minute). With a capacity of one, two requests are
always at least 15 s apart, so any 60-second window contains at most 4 of them, however
many workers compete. A larger capacity would allow bursts that break the provider's limit.

The bucket update runs as one Lua script, so two workers can never both take the last
token. The time comes from the caller (an injectable clock), which keeps the limiter
deterministic under test.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from redis import Redis

# KEYS[1] bucket; ARGV: now (s), refill rate (tokens/s), capacity, key TTL (s).
# Returns {1, 0} when a token was taken, else {0, milliseconds until one is available}.
_BUCKET_SCRIPT = """
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end
if now > ts then
  tokens = math.min(capacity, tokens + (now - ts) * rate)
  ts = now
end
local granted = 0
local wait_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  granted = 1
else
  wait_ms = math.ceil((1 - tokens) / rate * 1000)
end
-- %.17g: store the full float precision, so rounding never hands out an early token.
redis.call('HSET', KEYS[1], 'tokens', string.format('%.17g', tokens),
           'ts', string.format('%.17g', ts))
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return {granted, wait_ms}
"""


# The script rounds waits up to whole milliseconds; don't give up over that rounding.
_ROUNDING_SLACK = 0.002


class TokenBucket:
    def __init__(
        self,
        redis: Redis,
        key: str,
        rate_per_minute: float,
        *,
        capacity: int = 1,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_minute <= 0 or capacity < 1:
            raise ValueError("rate_per_minute must be positive and capacity at least 1")
        self._key = key
        self._rate = rate_per_minute / 60.0
        self._capacity = capacity
        self._clock = clock
        self._sleep = sleep
        self._ttl = max(60, int(capacity / self._rate) + 60)
        self._script = redis.register_script(_BUCKET_SCRIPT)

    def try_acquire(self) -> float:
        """Take a token if one is there; return 0, or the seconds to wait for the next one."""
        granted, wait_ms = self._script(
            keys=[self._key],
            args=[repr(self._clock()), repr(self._rate), self._capacity, self._ttl],
        )
        return 0.0 if int(granted) == 1 else max(int(wait_ms), 1) / 1000.0

    def acquire(self, max_wait: float) -> bool:
        """Wait up to ``max_wait`` seconds for a token. ``False`` means "give up, skip"."""
        deadline = self._clock() + max_wait + _ROUNDING_SLACK
        while True:
            wait = self.try_acquire()
            if wait == 0:
                return True
            if self._clock() + wait > deadline:
                return False
            self._sleep(wait)


class DailyBudget:
    """At most ``limit`` requests per UTC day (VirusTotal's free API allows 500)."""

    def __init__(
        self,
        redis: Redis,
        key_prefix: str,
        limit: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._limit = limit
        self._clock = clock

    def _key(self) -> str:
        day = datetime.fromtimestamp(self._clock(), UTC).date().isoformat()
        return f"{self._prefix}:{day}"

    def used(self) -> int:
        value = self._redis.get(self._key())
        return int(value) if value is not None else 0

    def exhausted(self) -> bool:
        return self.used() >= self._limit

    def spend(self) -> bool:
        """Count one request; ``False`` (do not send it) once the day's budget is used up."""
        key = self._key()
        with self._redis.pipeline() as pipe:
            pipe.incr(key)
            pipe.expire(key, 2 * 86400)
            count, _ = pipe.execute()
        return int(count) <= self._limit
