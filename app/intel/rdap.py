"""RDAP client: when was a domain registered?

RDAP (RFC 9082/9083) is the JSON successor of WHOIS. Which server answers for a TLD comes
from a bootstrap file in the IANA format. We ship a reviewed copy
(``rdap_bootstrap.json``) instead of downloading IANA's at runtime, so the set of servers
the worker can contact is fixed in the repository. A domain under any other TLD is
skipped, and the ``SENDER_NEW_DOMAIN`` rule simply does not fire.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.intel.http import json_object, raise_for_status, request_json
from app.intel.indicators import is_domain, tld
from app.intel.models import IntelResult

BOOTSTRAP_FILE = Path(__file__).with_name("rdap_bootstrap.json")


def load_bootstrap(path: Path = BOOTSTRAP_FILE) -> dict[str, str]:
    """TLD -> base URL (HTTPS only), from a file in the IANA ``dns.json`` format."""
    data = json.loads(path.read_text(encoding="utf-8"))
    servers: dict[str, str] = {}
    for tlds, urls in data["services"]:
        https = [u for u in urls if u.startswith("https://")]
        if not https:
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for name in tlds:
            servers[name.lower()] = base
    return servers


def bootstrap_hosts(servers: Mapping[str, str]) -> frozenset[str]:
    return frozenset(urlsplit(base).hostname or "" for base in servers.values()) - {""}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _registration_date(data: dict[str, Any]) -> datetime | None:
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict) or event.get("eventAction") != "registration":
            continue
        value = event.get("eventDate")
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


class RdapClient:
    provider = "rdap"

    def __init__(
        self,
        http: httpx.Client,
        servers: Mapping[str, str],
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._http = http
        self._servers = dict(servers)
        self._clock = clock

    def registration(self, domain: str) -> IntelResult:
        """Look up ``domain`` (a registered domain such as ``example.com``)."""
        if not is_domain(domain):
            return IntelResult.skipped("rdap", "not a domain name")
        base = self._servers.get(tld(domain))
        if base is None:
            return IntelResult.skipped("rdap", f"no RDAP server configured for .{tld(domain)}")
        status, data = request_json(
            self._http, "GET", f"{base}domain/{domain}", headers={"Accept": "application/rdap+json"}
        )
        fetched_at = self._clock()
        if status == 404:
            return IntelResult(
                provider="rdap", status="not_found", detail="no RDAP record", fetched_at=fetched_at
            )
        raise_for_status(status)
        registered = _registration_date(json_object(data))
        if registered is None:
            return IntelResult(
                provider="rdap",
                status="not_found",
                detail="the RDAP record has no registration date",
                fetched_at=fetched_at,
            )
        return IntelResult(
            provider="rdap",
            status="hit",
            detail=f"registered {registered.date().isoformat()}",
            raw={"domain": domain, "registered": registered.isoformat()},
            fetched_at=fetched_at,
        )
