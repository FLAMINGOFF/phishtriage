"""VirusTotal API v3 client: look up file hashes, URLs and domains.

Lookups only. This client has no method that uploads a file or submits a URL for
scanning: files sent to VirusTotal are shared with its customers, and an attachment may
hold confidential data. URLs are looked up by their identifier (``GET /urls/{id}``), which
never triggers a new scan.

The free public API allows 4 requests per minute and 500 per day and must not be used in
commercial products or services. Rate limiting and the daily budget live in
:mod:`app.intel.service`; this module only speaks HTTP.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.intel.http import json_object, raise_for_status, request_json
from app.intel.indicators import is_domain, is_sha256
from app.intel.models import IntelResult

HOST = "www.virustotal.com"
BASE_URL = f"https://{HOST}/api/v3"
_STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def url_id(url: str) -> str:
    """VirusTotal's URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class VirusTotalClient:
    provider = "virustotal"

    def __init__(
        self, http: httpx.Client, api_key: str, clock: Callable[[], datetime] = _utcnow
    ) -> None:
        self._http = http
        self._api_key = api_key
        self._clock = clock

    def file(self, sha256: str) -> IntelResult:
        if not is_sha256(sha256):
            return IntelResult.skipped("virustotal", "not a SHA-256 hash")
        return self._get(f"/files/{sha256}")

    def url(self, url: str) -> IntelResult:
        return self._get(f"/urls/{url_id(url)}")

    def domain(self, domain: str) -> IntelResult:
        if not is_domain(domain):
            return IntelResult.skipped("virustotal", "not a domain name")
        return self._get(f"/domains/{domain}")

    def _get(self, path: str) -> IntelResult:
        status, data = request_json(
            self._http, "GET", BASE_URL + path, headers={"x-apikey": self._api_key}
        )
        fetched_at = self._clock()
        if status == 404:
            return IntelResult(
                provider="virustotal",
                status="not_found",
                detail="unknown to VirusTotal",
                fetched_at=fetched_at,
            )
        raise_for_status(status)
        return self._parse(json_object(data), fetched_at)

    @staticmethod
    def _parse(data: dict[str, Any], fetched_at: datetime) -> IntelResult:
        attributes = json_object(json_object(data.get("data")).get("attributes"))
        stats_in = attributes.get("last_analysis_stats")
        stats = {
            key: value
            for key, value in (stats_in.items() if isinstance(stats_in, dict) else ())
            if key in _STATS and isinstance(value, int) and value >= 0
        }
        raw: dict[str, Any] = {"last_analysis_stats": stats}
        if isinstance(attributes.get("reputation"), int):
            raw["reputation"] = attributes["reputation"]
        analysed = attributes.get("last_analysis_date")
        if isinstance(analysed, int) and analysed > 0:
            raw["last_analysis_date"] = datetime.fromtimestamp(analysed, UTC).isoformat()

        total = sum(stats.values())
        if total == 0:
            return IntelResult(
                provider="virustotal",
                status="not_found",
                detail="known to VirusTotal but never analysed",
                raw=raw,
                fetched_at=fetched_at,
            )
        malicious = stats.get("malicious", 0)
        detail = f"{malicious}/{total} engines flag it malicious"
        if stats.get("suspicious"):
            detail += f", {stats['suspicious']} suspicious"
        return IntelResult(
            provider="virustotal",
            status="hit" if malicious > 0 else "clean",
            malicious_count=malicious,
            detail=detail,
            raw=raw,
            fetched_at=fetched_at,
        )
