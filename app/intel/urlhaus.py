"""URLhaus (abuse.ch) client: is a URL or host listed as distributing malware?

Queries only; nothing is ever submitted. Needs a free Auth-Key from https://auth.abuse.ch/.
Only URL-level listings count towards ``URL_INTEL_MALICIOUS``. A host listing is stored
for the analyst but does not score: shared hosting and URL shorteners often have one bad
URL among millions of good ones.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from app.intel.http import ProviderError, clip, json_object, raise_for_status, request_json
from app.intel.models import IntelResult

HOST = "urlhaus-api.abuse.ch"
BASE_URL = f"https://{HOST}/v1"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class URLhausClient:
    provider = "urlhaus"

    def __init__(
        self, http: httpx.Client, auth_key: str, clock: Callable[[], datetime] = _utcnow
    ) -> None:
        self._http = http
        self._auth_key = auth_key
        self._clock = clock

    def url(self, url: str) -> IntelResult:
        data, fetched_at = self._post("/url/", {"url": url})
        if data.get("query_status") == "no_results":
            return IntelResult(
                provider="urlhaus", status="not_found", detail="not listed", fetched_at=fetched_at
            )
        self._check(data)
        threat = clip(data.get("threat"), 64) or "malware"
        url_status = clip(data.get("url_status"), 32) or "unknown"
        tags = data.get("tags")
        raw: dict[str, Any] = {
            "url_status": url_status,
            "threat": threat,
            "date_added": clip(data.get("date_added"), 32),
            "tags": [clip(t, 64) for t in tags[:10] if isinstance(t, str)]
            if isinstance(tags, list)
            else [],
            "reference": clip(data.get("urlhaus_reference"), 200),
        }
        return IntelResult(
            provider="urlhaus",
            status="hit",
            detail=f"listed: {threat}, {url_status}",
            raw=raw,
            fetched_at=fetched_at,
        )

    def host(self, host: str) -> IntelResult:
        data, fetched_at = self._post("/host/", {"host": host})
        if data.get("query_status") == "no_results":
            return IntelResult(
                provider="urlhaus", status="not_found", detail="not listed", fetched_at=fetched_at
            )
        self._check(data)
        count = data.get("url_count")
        count = int(count) if isinstance(count, int | str) and str(count).isdigit() else None
        raw = {
            "url_count": count,
            "firstseen": clip(data.get("firstseen"), 32),
            "reference": clip(data.get("urlhaus_reference"), 200),
        }
        detail = "host listed" + (f" with {count} malware URL(s)" if count is not None else "")
        return IntelResult(
            provider="urlhaus", status="hit", detail=detail, raw=raw, fetched_at=fetched_at
        )

    def _post(self, path: str, form: dict[str, str]) -> tuple[dict[str, Any], datetime]:
        status, data = request_json(
            self._http, "POST", BASE_URL + path, data=form, headers={"Auth-Key": self._auth_key}
        )
        raise_for_status(status)
        return json_object(data), self._clock()

    @staticmethod
    def _check(data: dict[str, Any]) -> None:
        query_status = data.get("query_status")
        if query_status != "ok":
            raise ProviderError(f"URLhaus answered {clip(query_status, 40)!r}")
