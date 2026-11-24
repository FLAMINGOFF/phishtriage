"""Redis cache for intel answers, so the same indicator is not looked up again and again.

Keys hold a SHA-256 of the indicator, never the indicator itself: a URL can carry a
victim's email address or a token, and Redis keys show up in monitoring tools.
Only definite answers (hit / clean / not_found) are cached. A broken cache is a cache
miss, never a failed analysis.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timedelta

from pydantic import ValidationError
from redis import Redis
from redis.exceptions import RedisError

from app.intel.models import CACHEABLE_STATUSES, IntelResult, Provider

logger = logging.getLogger(__name__)

KEY_PREFIX = "intel:v1"

# Fixed by the plan for VirusTotal (24 h) and URLhaus (1 h). Registration dates do not
# change, so RDAP answers keep for a week.
TTL: dict[str, timedelta] = {
    "virustotal": timedelta(hours=24),
    "urlhaus": timedelta(hours=1),
    "rdap": timedelta(days=7),
}


def cache_key(provider: str, kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{KEY_PREFIX}:{provider}:{kind}:{digest}"


class IntelCache:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def get(self, provider: Provider, kind: str, value: str) -> IntelResult | None:
        try:
            cached = self._redis.get(cache_key(provider, kind, value))
        except RedisError as exc:
            logger.warning("intel cache unavailable: %s", exc)
            return None
        if cached is None:
            return None
        try:
            return IntelResult.model_validate_json(cached)
        except ValidationError:
            return None

    def put(self, kind: str, value: str, result: IntelResult) -> None:
        if result.status not in CACHEABLE_STATUSES:
            return
        try:
            self._redis.set(
                cache_key(result.provider, kind, value),
                result.model_dump_json(),
                ex=TTL[result.provider],
            )
        except RedisError as exc:
            logger.warning("intel cache unavailable: %s", exc)
