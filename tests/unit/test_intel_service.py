"""Intel orchestration: caching, rate limit, daily budget, per-report caps, failure modes.

The clock is fake: the rate-limit tests "wait" by advancing it, so they run instantly and
prove the limit exactly (acceptance criterion: at most 4 VirusTotal requests per minute).
"""

from __future__ import annotations

import itertools
import random
import re
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import pytest
import respx
from fakeredis import FakeRedis, FakeServer

from app.intel import rdap, urlhaus, virustotal
from app.intel.cache import IntelCache, cache_key
from app.intel.http import make_http_client
from app.intel.ratelimit import DailyBudget, TokenBucket
from app.intel.service import (
    MAX_LISTED_PER_PROVIDER,
    URLHAUS_MAX_LOOKUPS_PER_REPORT,
    IntelService,
    NoIntel,
    build_intel_service,
)

VT_FILES = re.compile(rf"^{re.escape(virustotal.BASE_URL)}/files/[0-9a-f]{{64}}$")
VT_URLS = re.compile(rf"^{re.escape(virustotal.BASE_URL)}/urls/.+$")
UH_URL = f"{urlhaus.BASE_URL}/url/"
UH_HOST = f"{urlhaus.BASE_URL}/host/"
RDAP_COM = "https://rdap.verisign.com/com/v1/"
START = datetime(2026, 11, 24, 9, 0, tzinfo=UTC).timestamp()


@dataclass(frozen=True)
class Obs:
    type: str
    value: str


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def sha(n: int) -> str:
    return f"{n:064x}"


def vt_answer(malicious: int = 0) -> dict[str, object]:
    stats = {"malicious": malicious, "harmless": 10, "undetected": 50}
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def make_service(fake_redis: FakeRedis, clock: FakeClock):
    http = make_http_client({virustotal.HOST, urlhaus.HOST, "rdap.verisign.com"}, timeout=5)

    def factory(
        *,
        redis: FakeRedis | None = None,
        vt: bool = True,
        uh: bool = True,
        rdap_on: bool = True,
        vt_max: int = 4,
        budget: int = 500,
        max_wait: float = 60.0,
        rate: int = 4,
    ) -> IntelService:
        conn = redis or fake_redis
        return IntelService(
            virustotal_client=virustotal.VirusTotalClient(http, "vt-key") if vt else None,
            urlhaus_client=urlhaus.URLhausClient(http, "uh-key") if uh else None,
            rdap_client=rdap.RdapClient(http, {"com": RDAP_COM}) if rdap_on else None,
            cache=IntelCache(conn),
            vt_bucket=TokenBucket(conn, "t:vt", rate, clock=clock, sleep=clock.sleep),
            vt_budget=DailyBudget(conn, "t:budget", budget, clock=clock),
            vt_max_per_report=vt_max,
            vt_daily_budget=budget,
            max_wait=max_wait,
        )

    return factory


# --------------------------------------------------------------------------- no keys


def test_without_keys_everything_is_skipped_and_nothing_is_sent(
    make_settings, fake_redis: FakeRedis, http_mock: respx.Router
) -> None:
    service = build_intel_service(make_settings(), fake_redis)
    observables = [
        Obs("url", "http://login.evil.example/a"),
        Obs("domain", "login.evil.example"),
        Obs("ip", "198.51.100.14"),
        Obs("email", "ceo@evil.example"),
        Obs("sha256", sha(1)),
    ]
    outcome = service.lookup(observables, "login.evil.example")
    assert not http_mock.calls
    statuses = {
        key: [(r.provider, r.status, r.detail) for r in results]
        for key, results in outcome.results.items()
    }
    assert statuses[("sha256", sha(1))] == [("virustotal", "skipped", "VT_API_KEY not set")]
    assert statuses[("url", "http://login.evil.example/a")] == [
        ("virustotal", "skipped", "VT_API_KEY not set"),
        ("urlhaus", "skipped", "URLHAUS_AUTH_KEY not set"),
    ]
    assert ("rdap", "skipped", "no RDAP server configured for .example") in statuses[
        ("domain", "login.evil.example")
    ]
    assert ("ip", "198.51.100.14") in statuses
    assert ("email", "ceo@evil.example") not in statuses  # no provider looks up addresses
    assert outcome.snapshot.urls[observables[0].value][0].status == "skipped"
    assert not outcome.snapshot.domain_registered


def test_rdap_can_be_disabled(make_settings, fake_redis: FakeRedis) -> None:
    service = build_intel_service(make_settings(rdap_enabled=False), fake_redis)
    outcome = service.lookup([Obs("domain", "evil.com")], "evil.com")
    assert outcome.results[("domain", "evil.com")][-1].detail == ("disabled by RDAP_ENABLED=false")


def test_no_intel_and_construction_guard() -> None:
    assert NoIntel().lookup([Obs("url", "http://x.example/")], None).results == {}
    with pytest.raises(ValueError, match="rate limiter"):
        IntelService(
            virustotal_client=object(),  # type: ignore[arg-type]
            urlhaus_client=None,
            rdap_client=None,
            cache=None,
            vt_bucket=None,
            vt_budget=None,
        )


# --------------------------------------------------------------------------- results


def test_hits_reach_the_snapshot(make_service, http_mock: respx.Router) -> None:
    url = "http://login.evil-bank.com/x"
    http_mock.get(url=VT_FILES).respond(json=vt_answer(malicious=7))
    http_mock.get(url=VT_URLS).respond(json=vt_answer(malicious=0))
    http_mock.get(f"{virustotal.BASE_URL}/domains/login.evil-bank.com").respond(
        json=vt_answer(malicious=1)
    )
    http_mock.post(UH_URL).respond(
        json={"query_status": "ok", "url_status": "online", "threat": "malware_download"}
    )
    http_mock.post(UH_HOST).respond(json={"query_status": "ok", "url_count": 3})
    http_mock.get(f"{RDAP_COM}domain/evil-bank.com").respond(
        json={"events": [{"eventAction": "registration", "eventDate": "2026-11-20T00:00:00Z"}]}
    )
    service = make_service()
    outcome = service.lookup(
        [Obs("sha256", sha(9)), Obs("url", url), Obs("domain", "login.evil-bank.com")],
        "login.evil-bank.com",
    )
    snapshot = outcome.snapshot
    assert [r.is_malicious for r in snapshot.hashes[sha(9)]] == [True]
    assert [(r.provider, r.is_malicious) for r in snapshot.urls[url]] == [
        ("virustotal", False),
        ("urlhaus", True),
    ]
    assert snapshot.domain_registered == {"evil-bank.com": datetime(2026, 11, 20, tzinfo=UTC)}
    domain_results = outcome.results[("domain", "login.evil-bank.com")]
    assert [(r.provider, r.status) for r in domain_results] == [
        ("virustotal", "hit"),
        ("urlhaus", "hit"),  # host listing: stored for the analyst, never scored
        ("rdap", "hit"),
    ]


def test_answers_are_cached_with_the_planned_ttls(
    make_service, fake_redis: FakeRedis, http_mock: respx.Router
) -> None:
    url = "http://evil.example/p"
    vt_route = http_mock.get(url=VT_URLS).respond(json=vt_answer(malicious=4))
    uh_route = http_mock.post(UH_URL).respond(json={"query_status": "no_results"})
    service = make_service()
    first = service.lookup([Obs("url", url)], None)
    second = make_service().lookup([Obs("url", url)], None)  # e.g. another worker
    assert vt_route.call_count == 1
    assert uh_route.call_count == 1
    assert first.results == second.results
    assert 86_000 < fake_redis.ttl(cache_key("virustotal", "url", url)) <= 86_400
    assert 3_500 < fake_redis.ttl(cache_key("urlhaus", "url", url)) <= 3_600
    # The key never contains the indicator itself.
    assert all(b"evil" not in key for key in fake_redis.keys("intel:v1:*"))


def test_errors_are_not_cached_and_stop_that_provider_for_the_report(
    make_service, http_mock: respx.Router
) -> None:
    route = http_mock.get(url=VT_FILES).respond(429, json={"error": {"code": "QuotaExceeded"}})
    service = make_service(uh=False)
    outcome = service.lookup([Obs("sha256", sha(1)), Obs("sha256", sha(2))], None)
    first, second = outcome.results[("sha256", sha(1))][0], outcome.results[("sha256", sha(2))][0]
    assert (first.status, first.detail) == ("error", "provider rate limit or quota exceeded")
    assert second.status == "skipped"
    assert second.detail == (
        "skipped after an earlier error (provider rate limit or quota exceeded)"
    )
    assert route.call_count == 1
    service.lookup([Obs("sha256", sha(1))], None)
    assert route.call_count == 2  # the error was not cached


def test_unexpected_client_failure_is_an_error_result(
    make_service, monkeypatch: pytest.MonkeyPatch, http_mock: respx.Router
) -> None:
    def broken(self: object, value: str) -> None:
        raise KeyError("attributes")

    monkeypatch.setattr(virustotal.VirusTotalClient, "file", broken)
    outcome = make_service().lookup([Obs("sha256", sha(1))], None)
    result = outcome.results[("sha256", sha(1))][0]
    assert (result.status, result.detail) == ("error", "unexpected error (KeyError)")


# --------------------------------------------------------------------------- limits


def test_per_report_cap_prefers_hashes(make_service, http_mock: respx.Router) -> None:
    files = http_mock.get(url=VT_FILES).respond(json=vt_answer())
    urls = http_mock.get(url=VT_URLS).respond(json=vt_answer())
    observables = [Obs("url", f"http://e{i}.example/") for i in range(3)] + [
        Obs("sha256", sha(i)) for i in range(3)
    ]
    outcome = make_service(uh=False, vt_max=4).lookup(observables, None)
    assert files.call_count == 3  # hashes first ...
    assert urls.call_count == 1  # ... then URLs, until the cap
    skipped = [
        r
        for results in outcome.results.values()
        for r in results
        if r.provider == "virustotal" and r.status == "skipped"
    ]
    assert [r.detail for r in skipped] == ["per-report limit of 4 lookups reached"] * 2


def test_urlhaus_cap_and_listing_bound(make_service, http_mock: respx.Router) -> None:
    route = http_mock.post(UH_URL).respond(json={"query_status": "no_results"})
    observables = [Obs("url", f"http://e{i}.example/") for i in range(60)]
    outcome = make_service(vt=False).lookup(observables, None)
    assert route.call_count == URLHAUS_MAX_LOOKUPS_PER_REPORT
    listed = [r for results in outcome.results.values() for r in results if r.provider == "urlhaus"]
    assert len(listed) == MAX_LISTED_PER_PROVIDER


def test_daily_budget(make_service, clock: FakeClock, http_mock: respx.Router) -> None:
    route = http_mock.get(url=VT_FILES).respond(json=vt_answer())
    service = make_service(uh=False, budget=2, vt_max=10)
    outcome = service.lookup([Obs("sha256", sha(i)) for i in range(4)], None)
    assert route.call_count == 2
    details = [outcome.results[("sha256", sha(i))][0].detail for i in range(2, 4)]
    assert details == ["daily budget of 2 lookups used"] * 2

    clock.now += 24 * 3600  # a new UTC day, a new budget
    service.lookup([Obs("sha256", sha(i)) for i in range(10, 12)], None)
    assert route.call_count == 4


def test_rate_limit_skips_instead_of_waiting_too_long(
    make_service, clock: FakeClock, http_mock: respx.Router
) -> None:
    route = http_mock.get(url=VT_FILES).respond(json=vt_answer())
    started = clock.now
    outcome = make_service(uh=False, max_wait=10, vt_max=10).lookup(
        [Obs("sha256", sha(i)) for i in range(3)], None
    )
    assert route.call_count == 1  # the next slot is 15 s away, more than we may wait
    assert [outcome.results[("sha256", sha(i))][0].detail for i in (1, 2)] == [
        "rate limit: no request slot within 10 s"
    ] * 2
    assert clock.now == started  # gave up at once instead of sleeping in vain


def test_limiter_failure_fails_closed(make_service, http_mock: respx.Router) -> None:
    server = FakeServer()
    server.connected = False  # Redis is down
    route = http_mock.get(url=VT_FILES).respond(json=vt_answer())
    outcome = make_service(redis=FakeRedis(server=server), uh=False).lookup(
        [Obs("sha256", sha(1))], None
    )
    assert not route.called  # never sent without the shared limiter
    assert outcome.results[("sha256", sha(1))][0].detail == "rate limiter unavailable"


def test_virustotal_never_gets_more_than_4_requests_a_minute(
    make_service, clock: FakeClock, http_mock: respx.Router
) -> None:
    """Acceptance (M3): with the free API settings, no 60-second window holds 5 requests."""
    sent: list[float] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(clock())
        return httpx.Response(200, json=vt_answer())

    http_mock.get(url=VT_FILES).mock(side_effect=answer)
    service = make_service(uh=False, rdap_on=False)
    for report in range(6):  # six reports, four fresh hashes each
        service.lookup([Obs("sha256", sha(report * 10 + i)) for i in range(4)], None)

    assert len(sent) == 24
    for i in range(len(sent) - 4):
        assert sent[i + 4] - sent[i] >= 60.0
    assert min(b - a for a, b in itertools.pairwise(sent)) >= 15.0
    assert sent[-1] - sent[0] == pytest.approx(23 * 15.0, abs=0.1)  # and no slower than needed


def test_bucket_holds_with_many_competing_workers(fake_redis: FakeRedis) -> None:
    """Random attempts from 8 workers sharing one bucket: grants stay 15 s apart."""
    clock = FakeClock()
    rng = random.Random(4)  # noqa: S311 - test data
    buckets = [
        TokenBucket(fake_redis, "t:shared", 4, clock=clock, sleep=clock.sleep) for _ in range(8)
    ]
    granted: list[float] = []
    for _ in range(2000):
        clock.now += rng.uniform(0, 3)
        if rng.choice(buckets).try_acquire() == 0:
            granted.append(clock.now)
    assert len(granted) > 50
    for i in range(len(granted) - 4):
        assert granted[i + 4] - granted[i] >= 60.0


def test_bucket_wait_hint_and_validation(fake_redis: FakeRedis) -> None:
    clock = FakeClock()
    bucket = TokenBucket(fake_redis, "t:b", 4, clock=clock, sleep=clock.sleep)
    assert bucket.try_acquire() == 0
    assert bucket.try_acquire() == pytest.approx(15.0, abs=0.002)
    clock.now += 5
    assert bucket.try_acquire() == pytest.approx(10.0, abs=0.002)
    assert bucket.acquire(max_wait=10)  # sleeps exactly until the next token
    assert clock.now == pytest.approx(START + 15, abs=0.002)
    with pytest.raises(ValueError, match="positive"):
        TokenBucket(fake_redis, "t:x", 0)


def test_daily_budget_counts_per_utc_day(fake_redis: FakeRedis) -> None:
    clock = FakeClock()
    budget = DailyBudget(fake_redis, "t:day", 2, clock=clock)
    assert budget.spend()
    assert budget.spend()
    assert not budget.spend()
    assert budget.exhausted()
    assert budget.used() == 3
    clock.now += 86400
    assert budget.used() == 0
    assert not budget.exhausted()
    assert 0 < fake_redis.ttl(f"t:day:{datetime.fromtimestamp(START, UTC).date()}") <= 2 * 86400
