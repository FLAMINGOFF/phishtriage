"""Defang and refang indicators.

A defanged indicator (``hxxps://login-example[.]com``) cannot be clicked, auto-linked by
a mail client or chat tool, or pasted into a browser by accident. Analysts see IOCs only
in this form; exports and threat-intel lookups use the real value.
"""

from __future__ import annotations

import re

_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_SCHEME_RE = re.compile(r"^(https?|ftp)(?=://)", re.IGNORECASE)


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    if ":" in ip:  # IPv6
        return ip.replace(":", "[:]")
    return ip.replace(".", "[.]")


def defang_email(address: str) -> str:
    local, sep, domain = address.rpartition("@")
    if not sep:
        return defang_domain(address)
    return f"{local}[@]{defang_domain(domain)}"


def defang_url(url: str) -> str:
    """``https://login.example.com/a`` -> ``hxxps://login[.]example[.]com/a``.

    The scheme and the dots (and any ``@``) of the authority are broken; the path and query
    stay readable for the analyst.
    """
    match = _SCHEME_RE.match(url)
    if match:
        scheme = match.group(1).lower()
        rest = url[match.end() :]  # starts with ://
        prefix = _SCHEMES[scheme]
    else:
        scheme_end = url.find("://")
        prefix, rest = (url[:scheme_end], url[scheme_end:]) if scheme_end > 0 else ("", url)
    if not rest.startswith("://"):
        return prefix + defang_domain(rest)
    authority_end = len(rest)
    for sep in "/?#":
        pos = rest.find(sep, 3)
        if pos != -1:
            authority_end = min(authority_end, pos)
    authority = rest[3:authority_end]
    tail = rest[authority_end:]
    authority = authority.replace("@", "[@]").replace(".", "[.]")
    return f"{prefix}://{authority}{tail}"


def defang(value: str, kind: str) -> str:
    """Defang ``value`` of observable type ``kind`` (url, domain, ip, email, sha256)."""
    if kind == "url":
        return defang_url(value)
    if kind == "domain":
        return defang_domain(value)
    if kind == "ip":
        return defang_ip(value)
    if kind == "email":
        return defang_email(value)
    return value  # hashes are harmless


_REFANG = [
    (re.compile(r"\bhxxp(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bfxp(?=\[?:)", re.IGNORECASE), "ftp"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}", re.IGNORECASE), "."),
    (re.compile(r"\[(?:@|at)\]|\((?:@|at)\)", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    """Undo common defanging styles (``[.]``, ``(dot)``, ``hxxp``, ``[@]``, ``[://]``)."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text
