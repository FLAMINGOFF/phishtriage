"""Extract indicators of compromise (IOCs) from a parsed email.

Sources: URLs in the plain-text body, URLs in HTML attributes (links, forms, images,
frames), sender addresses and domains, the originating IP from the Received chain, and
attachment hashes. The organisation's own domains are never reported as IOCs: a link to
the real university login page inside a phish is bait, not an indicator.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

from app.parsing.defang import defang
from app.parsing.domains import is_subdomain_or_same, parse_ip, to_ascii
from app.parsing.eml import ParsedEmail
from app.parsing.html import analyze_html
from app.parsing.received import origin_ip

ObservableType = Literal["url", "domain", "ip", "email", "sha256"]

MAX_URL_CHARS = 2048
MAX_OBSERVABLES = 500
MAX_SCAN_CHARS = 2_000_000

# Linear-time pattern (no nested quantifiers), bounded length: safe on hostile input.
_URL_RE = re.compile(r"(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>\"'`\x00-\x1f\x7f\\^{}|]{1,2048}")
_TRAILING = ".,;:!?*'\")]}>"
_ALLOWED_SCHEMES = {"http", "https", "ftp"}


class Observable(BaseModel):
    type: ObservableType
    value: str
    defanged: str


def _trim(candidate: str) -> str:
    """Drop trailing punctuation, keeping balanced brackets (wiki-style URLs)."""
    while candidate and candidate[-1] in _TRAILING:
        last = candidate[-1]
        opening = {")": "(", "]": "[", "}": "{"}.get(last)
        if opening and candidate.count(opening) >= candidate.count(last):
            break
        candidate = candidate[:-1]
    return candidate


def find_urls(text: str) -> list[str]:
    """URLs written out in plain text (``http://``, ``https://``, ``ftp://``, ``www.``)."""
    found: list[str] = []
    for match in _URL_RE.finditer(text[:MAX_SCAN_CHARS]):
        url = _trim(match.group(0))
        if url.lower().startswith("www."):
            url = "http://" + url
        normalized = normalize_url(url)
        if normalized:
            found.append(normalized)
    return found


def normalize_url(url: str) -> str | None:
    """Lower-case scheme and host, punycode the host; ``None`` if it is not a web URL."""
    url = url.strip()[:MAX_URL_CHARS]
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_SCHEMES or not host:
        return None
    # IP hosts keep their spelling (``http://3232235777/`` is evidence in itself); names
    # are lower-cased and punycoded so the same host always compares equal.
    if ":" in host:
        host = f"[{host}]"
    elif parse_ip(host) is None:
        host = to_ascii(host)
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = (f"{userinfo}@" if userinfo else "") + host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def url_host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host or None


def _is_own(host_or_domain: str, own_domains: Collection[str]) -> bool:
    return any(is_subdomain_or_same(host_or_domain, own) for own in own_domains)


def email_urls(parsed: ParsedEmail) -> list[str]:
    """All URLs in the email, in order of appearance, without duplicates."""
    urls = find_urls(parsed.body_text)
    if parsed.body_html:
        for link in analyze_html(parsed.body_html).links:
            normalized = normalize_url(link.url)
            if normalized:
                urls.append(normalized)
        urls.extend(find_urls(analyze_html(parsed.body_html).text))
    return list(dict.fromkeys(urls))


def mailto_addresses(parsed: ParsedEmail) -> list[str]:
    if not parsed.body_html:
        return []
    result = []
    for link in analyze_html(parsed.body_html).links:
        if link.url.lower().startswith("mailto:"):
            address = link.url[7:].split("?", 1)[0].strip()
            if "@" in address:
                local, _, domain = address.rpartition("@")
                result.append(f"{local}@{to_ascii(domain)}")
    return result


def extract_observables(parsed: ParsedEmail, own_domains: Collection[str] = ()) -> list[Observable]:
    seen: dict[tuple[str, str], Observable] = {}

    def add(kind: ObservableType, value: str) -> None:
        value = value.strip()
        if not value or len(seen) >= MAX_OBSERVABLES or (kind, value) in seen:
            return
        seen[(kind, value)] = Observable(type=kind, value=value, defanged=defang(value, kind))

    def add_host(host: str) -> None:
        ip = parse_ip(host)
        if ip is not None:
            add("ip", str(ip))
        elif not _is_own(host, own_domains):
            add("domain", to_ascii(host))

    for url in email_urls(parsed):
        host = url_host(url)
        if host is None or (parse_ip(host) is None and _is_own(host, own_domains)):
            continue
        add("url", url)
        add_host(host)

    if not parsed.forwarded_inline:  # for inline forwards these are the reporter's own
        senders: Iterable[str] = [
            *(a.address for a in ([parsed.from_addr] if parsed.from_addr else [])),
            *(a.address for a in parsed.reply_to),
            *([parsed.return_path] if parsed.return_path and "@" in parsed.return_path else []),
        ]
        for address in senders:
            domain = address.rpartition("@")[2]
            if not _is_own(domain, own_domains):
                add("email", address.lower())
                add_host(domain)
        ip = origin_ip(parsed.received)
        if ip:
            add("ip", ip)

    for address in mailto_addresses(parsed):
        if not _is_own(address.rpartition("@")[2], own_domains):
            add("email", address.lower())

    for attachment in parsed.attachments:
        add("sha256", attachment.sha256)

    return list(seen.values())
