"""Redis connections.

Two kinds on purpose. The long-lived client has no read timeout, because an RQ worker
blocks on BLPOP for minutes and a socket timeout would break that. Health probes use a
throwaway client with short timeouts so a hung Redis cannot hang /readyz.
"""

from __future__ import annotations

from functools import lru_cache

from redis import Redis

from app.config import get_settings

PROBE_TIMEOUT_SECONDS = 2.0


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    """Shared client for the queue, cache and rate limits."""
    return Redis.from_url(get_settings().redis_url, socket_connect_timeout=5)


def redis_client(url: str, timeout: float = 5.0) -> Redis:
    """A client for short commands (enqueue from the web process): it never blocks long."""
    return Redis.from_url(url, socket_connect_timeout=timeout, socket_timeout=timeout)


def ping_redis(url: str) -> None:
    """Raise if Redis at ``url`` does not answer PING quickly."""
    client = Redis.from_url(
        url, socket_connect_timeout=PROBE_TIMEOUT_SECONDS, socket_timeout=PROBE_TIMEOUT_SECONDS
    )
    try:
        client.ping()
    finally:
        client.close()
