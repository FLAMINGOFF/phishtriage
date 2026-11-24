"""HTTP plumbing shared by the threat-intel clients.

Every request goes to a host that is fixed in this code base: VirusTotal, URLhaus and the
RDAP servers listed in ``rdap_bootstrap.json``. A request hook refuses any other host, so
even a bug that built a URL from email content could not make the worker fetch an
attacker's link (SSRF) or reveal the server's address to the attacker.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from typing import Any

import httpx

from app import __version__

# Provider answers are small JSON documents; anything bigger is refused, not buffered.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
USER_AGENT = f"PhishTriage/{__version__}"


class ProviderError(Exception):
    """A lookup failed. The message is short and safe to store and show to analysts."""


def make_http_client(
    allowed_hosts: Collection[str],
    timeout: float,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """An HTTPS-only client that can only reach ``allowed_hosts`` and never follows redirects."""
    allowed = frozenset(host.lower() for host in allowed_hosts)

    def only_allowed_hosts(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host.lower() not in allowed:
            raise ProviderError(f"refusing request to non-allowlisted host {request.url.host!r}")

    return httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        event_hooks={"request": [only_allowed_hosts]},
        transport=transport,
    )


def request_json(
    client: httpx.Client, method: str, url: str, **kwargs: Any
) -> tuple[int, Any | None]:
    """Send a request; return the status code and the decoded JSON body (``None`` if none).

    Network failures, redirects and oversized bodies raise :class:`ProviderError`.
    """
    try:
        with client.stream(method, url, **kwargs) as response:
            if response.is_redirect:
                raise ProviderError(f"unexpected redirect (HTTP {response.status_code})")
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                raise ProviderError("response too large")
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ProviderError("response too large")
            status = response.status_code
    except httpx.TimeoutException as exc:
        raise ProviderError("timed out") from exc
    except httpx.HTTPError as exc:
        raise ProviderError(f"network error ({type(exc).__name__})") from exc
    if not body:
        return status, None
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def raise_for_status(status: int) -> None:
    """Turn the HTTP status of a lookup into a :class:`ProviderError` unless it is 200."""
    if status == 200:
        return
    if status in (401, 403):
        raise ProviderError("authentication failed: check the API key")
    if status == 429:
        raise ProviderError("provider rate limit or quota exceeded")
    if status >= 500:
        raise ProviderError(f"provider error (HTTP {status})")
    raise ProviderError(f"unexpected response (HTTP {status})")


def json_object(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProviderError("invalid response (not a JSON object)")
    return data


def clip(value: Any, limit: int = 200) -> str | None:
    """A provider-supplied string, shortened; ``None`` for anything that is not a string."""
    return value[:limit] if isinstance(value, str) else None
