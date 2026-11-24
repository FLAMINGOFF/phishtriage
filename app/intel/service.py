"""Look up a report's indicators with every configured provider, within the limits.

What is looked up, and where:

* VirusTotal: attachment hashes, then URLs, then domains (that order, because a hash hit
  is the strongest evidence and the free API allows only a few lookups per report).
* URLhaus: URLs (``/url/``), and domains and IPs (``/host/``).
* RDAP: the registered domain of the sender, for ``SENDER_NEW_DOMAIN``.

Nothing here ever fails the analysis. A missing key, the rate limit, the daily budget or a
provider error each become a ``skipped`` or ``error`` result that is stored with the
report, and the rules simply see no intel for that indicator. After a provider fails once,
the rest of that report's lookups with it are skipped instead of waiting for more timeouts.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError

from app.config import Settings
from app.intel import rdap, urlhaus, virustotal
from app.intel.cache import IntelCache
from app.intel.http import ProviderError, make_http_client
from app.intel.models import IntelResult, IntelSnapshot, Provider
from app.intel.ratelimit import DailyBudget, TokenBucket
from app.parsing.domains import registered_domain, to_ascii

logger = logging.getLogger(__name__)

# Bounds the rows stored per provider and report; indicators beyond it are not listed.
MAX_LISTED_PER_PROVIDER = 50
URLHAUS_MAX_LOOKUPS_PER_REPORT = 20

VT_RATE_KEY = "intel:ratelimit:virustotal"
VT_BUDGET_KEY = "intel:budget:virustotal"

Key = tuple[str, str]  # (observable type, value)


class ObservableLike(Protocol):
    @property
    def type(self) -> str: ...
    @property
    def value(self) -> str: ...


@dataclass(frozen=True)
class IntelOutcome:
    """Results per observable (for storage) and the snapshot the rules see."""

    results: dict[Key, tuple[IntelResult, ...]] = field(default_factory=dict)
    snapshot: IntelSnapshot = field(default_factory=IntelSnapshot)


class IntelLookup(Protocol):
    def lookup(
        self, observables: Sequence[ObservableLike], sender_host: str | None
    ) -> IntelOutcome: ...


class NoIntel:
    """No lookups at all (the offline CLI)."""

    def lookup(
        self, observables: Sequence[ObservableLike], sender_host: str | None
    ) -> IntelOutcome:
        return IntelOutcome()


@dataclass
class _ReportState:
    """Per-report bookkeeping: fresh lookups made, and providers that gave up."""

    fresh: dict[str, int] = field(default_factory=dict)
    stopped: dict[str, str] = field(default_factory=dict)


class IntelService:
    def __init__(
        self,
        *,
        virustotal_client: virustotal.VirusTotalClient | None,
        urlhaus_client: urlhaus.URLhausClient | None,
        rdap_client: rdap.RdapClient | None,
        cache: IntelCache | None,
        vt_bucket: TokenBucket | None,
        vt_budget: DailyBudget | None,
        vt_max_per_report: int = 4,
        vt_daily_budget: int = 500,
        max_wait: float = 60.0,
        rdap_disabled_reason: str = "disabled by RDAP_ENABLED=false",
    ) -> None:
        if virustotal_client is not None and (vt_bucket is None or vt_budget is None):
            raise ValueError("VirusTotal lookups need the rate limiter and the daily budget")
        self._vt = virustotal_client
        self._urlhaus = urlhaus_client
        self._rdap = rdap_client
        self._cache = cache
        self._vt_bucket = vt_bucket
        self._vt_budget = vt_budget
        self._vt_max = vt_max_per_report
        self._vt_daily = vt_daily_budget
        self._max_wait = max_wait
        self._rdap_disabled = rdap_disabled_reason

    # ------------------------------------------------------------------ entry point

    def lookup(
        self, observables: Sequence[ObservableLike], sender_host: str | None
    ) -> IntelOutcome:
        state = _ReportState()
        results: dict[Key, list[IntelResult]] = {}
        by_type: dict[str, list[str]] = {}
        for observable in observables:
            by_type.setdefault(observable.type, []).append(observable.value)

        vt_targets = (
            [("sha256", value) for value in by_type.get("sha256", [])]
            + [("url", value) for value in by_type.get("url", [])]
            + [("domain", value) for value in by_type.get("domain", [])]
        )
        for key in vt_targets[:MAX_LISTED_PER_PROVIDER]:
            results.setdefault(key, []).append(self._virustotal(key, state))

        urlhaus_targets = [("url", value) for value in by_type.get("url", [])] + [
            (kind, value) for kind in ("domain", "ip") for value in by_type.get(kind, [])
        ]
        for key in urlhaus_targets[:MAX_LISTED_PER_PROVIDER]:
            results.setdefault(key, []).append(self._urlhaus_lookup(key, state))

        if sender_host:
            host_key = ("domain", to_ascii(sender_host))
            # Only external senders have a domain observable (our own domains are not IOCs).
            if host_key[1] in by_type.get("domain", []):
                results.setdefault(host_key, []).append(
                    self._rdap_lookup(registered_domain(host_key[1]), state)
                )

        frozen = {key: tuple(items) for key, items in results.items()}
        return IntelOutcome(results=frozen, snapshot=self._snapshot(frozen))

    @staticmethod
    def _snapshot(results: dict[Key, tuple[IntelResult, ...]]) -> IntelSnapshot:
        urls = {value: items for (kind, value), items in results.items() if kind == "url"}
        hashes = {value: items for (kind, value), items in results.items() if kind == "sha256"}
        registered: dict[str, datetime] = {}
        for items in results.values():
            for item in items:
                if item.provider == "rdap" and item.status == "hit":
                    domain, when = item.raw.get("domain"), item.raw.get("registered")
                    if isinstance(domain, str) and isinstance(when, str):
                        registered[domain] = datetime.fromisoformat(when)
        return IntelSnapshot(urls=urls, hashes=hashes, domain_registered=registered)

    # ------------------------------------------------------------------ providers

    def _virustotal(self, key: Key, state: _ReportState) -> IntelResult:
        client = self._vt
        if client is None:
            return IntelResult.skipped("virustotal", "VT_API_KEY not set")
        kind, value = key
        endpoint: dict[str, tuple[str, Callable[[str], IntelResult]]] = {
            "sha256": ("file", client.file),
            "url": ("url", client.url),
            "domain": ("domain", client.domain),
        }
        cache_kind, call = endpoint[kind]
        cached = self._cached("virustotal", cache_kind, value)
        if cached is not None:
            return cached
        refusal = self._vt_admission(state)
        if refusal is not None:
            return IntelResult.skipped("virustotal", refusal)
        return self._fresh("virustotal", cache_kind, value, call, state)

    def _vt_admission(self, state: _ReportState) -> str | None:
        """Why a fresh VirusTotal request may not be sent now, or ``None`` if it may."""
        if "virustotal" in state.stopped:
            return state.stopped["virustotal"]
        if state.fresh.get("virustotal", 0) >= self._vt_max:
            return f"per-report limit of {self._vt_max} lookups reached"
        bucket, budget = self._vt_bucket, self._vt_budget
        if bucket is None or budget is None:  # guarded in __init__; never send unthrottled
            return "rate limiter not configured"
        try:
            if budget.exhausted():
                reason = f"daily budget of {self._vt_daily} lookups used"
            elif not bucket.acquire(self._max_wait):
                reason = f"rate limit: no request slot within {self._max_wait:g} s"
            elif not budget.spend():
                reason = f"daily budget of {self._vt_daily} lookups used"
            else:
                return None
        except RedisError:
            # Fail closed: without the shared limiter we could exceed the provider's limit.
            logger.warning("VirusTotal rate limiter unavailable", exc_info=True)
            reason = "rate limiter unavailable"
        state.stopped["virustotal"] = reason
        return reason

    def _urlhaus_lookup(self, key: Key, state: _ReportState) -> IntelResult:
        client = self._urlhaus
        if client is None:
            return IntelResult.skipped("urlhaus", "URLHAUS_AUTH_KEY not set")
        kind, value = key
        cache_kind, call = ("url", client.url) if kind == "url" else ("host", client.host)
        cached = self._cached("urlhaus", cache_kind, value)
        if cached is not None:
            return cached
        if "urlhaus" in state.stopped:
            return IntelResult.skipped("urlhaus", state.stopped["urlhaus"])
        if state.fresh.get("urlhaus", 0) >= URLHAUS_MAX_LOOKUPS_PER_REPORT:
            return IntelResult.skipped(
                "urlhaus", f"per-report limit of {URLHAUS_MAX_LOOKUPS_PER_REPORT} lookups reached"
            )
        return self._fresh("urlhaus", cache_kind, value, call, state)

    def _rdap_lookup(self, domain: str, state: _ReportState) -> IntelResult:
        if self._rdap is None:
            return IntelResult.skipped("rdap", self._rdap_disabled)
        cached = self._cached("rdap", "domain", domain)
        if cached is not None:
            return cached
        return self._fresh("rdap", "domain", domain, self._rdap.registration, state)

    # ------------------------------------------------------------------ plumbing

    def _cached(self, provider: Provider, kind: str, value: str) -> IntelResult | None:
        return self._cache.get(provider, kind, value) if self._cache is not None else None

    def _fresh(
        self,
        provider: Provider,
        kind: str,
        value: str,
        call: Callable[[str], IntelResult],
        state: _ReportState,
    ) -> IntelResult:
        state.fresh[provider] = state.fresh.get(provider, 0) + 1
        try:
            result = call(value)
        except ProviderError as exc:
            result = IntelResult.error(provider, str(exc))
        except Exception as exc:
            logger.exception("%s lookup failed", provider)
            result = IntelResult.error(provider, f"unexpected error ({type(exc).__name__})")
        if result.status == "error":
            state.stopped[provider] = f"skipped after an earlier error ({result.detail})"
        elif self._cache is not None:
            self._cache.put(kind, value, result)
        return result


def build_intel_service(settings: Settings, redis: Redis) -> IntelService:
    """The worker's intel service, from settings. Keys are optional; RDAP needs none."""
    servers = rdap.load_bootstrap()
    allowed = {virustotal.HOST, urlhaus.HOST} | rdap.bootstrap_hosts(servers)
    http = make_http_client(allowed, settings.intel_timeout_seconds)
    vt_key = settings.vt_api_key.get_secret_value() if settings.vt_api_key else None
    urlhaus_key = (
        settings.urlhaus_auth_key.get_secret_value() if settings.urlhaus_auth_key else None
    )
    return IntelService(
        virustotal_client=virustotal.VirusTotalClient(http, vt_key) if vt_key else None,
        urlhaus_client=urlhaus.URLhausClient(http, urlhaus_key) if urlhaus_key else None,
        rdap_client=rdap.RdapClient(http, servers) if settings.rdap_enabled else None,
        cache=IntelCache(redis),
        vt_bucket=TokenBucket(redis, VT_RATE_KEY, settings.vt_rate_per_minute),
        vt_budget=DailyBudget(redis, VT_BUDGET_KEY, settings.vt_daily_budget),
        vt_max_per_report=settings.vt_max_lookups_per_report,
        vt_daily_budget=settings.vt_daily_budget,
        max_wait=settings.intel_max_wait_seconds,
    )
