"""Host name and IP helpers shared by parsing and the analyzers.

Everything here is pure and offline. ``tldextract`` uses the public-suffix snapshot that
ships with the package and never downloads a fresh list at runtime.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import idna
import tldextract

# RFC 2606 / RFC 6761 reserved TLDs are treated as public suffixes, so that demo hosts
# like "login.evil.example" have a registered domain ("evil.example") just like real ones.
RESERVED_SUFFIXES = ("example", "invalid", "localhost", "test")

_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, extra_suffixes=RESERVED_SUFFIXES
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def to_ascii(host: str) -> str:
    """Lower-case ``host`` and convert internationalised labels to punycode (xn--).

    Hostile input may not be valid IDNA at all; then we fall back to the lenient
    IDNA 2003 codec and finally to the lower-cased input, so extraction never fails.
    """
    host = host.strip().rstrip(".").lower()
    if not host or host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def to_unicode(host: str) -> str:
    """Best-effort reverse of :func:`to_ascii`, for display and homoglyph checks."""
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """``login.mail.example.co.uk`` -> ``example.co.uk``; the host itself if unknown."""
    host = to_ascii(host)
    if parse_ip(host) is not None:
        return host
    result = _extract(host)
    return result.top_domain_under_public_suffix or host


def is_subdomain_or_same(host: str, domain: str) -> bool:
    host, domain = to_ascii(host), to_ascii(domain)
    return host == domain or host.endswith("." + domain)


def parse_ip(host: str) -> IPAddress | None:
    """Parse ``host`` as an IP address, including the forms browsers accept.

    Phishing links hide IPs as ``http://3232235777/`` (decimal), ``http://0xc0a80001/``
    (hex) or ``http://0300.0250.0.1/`` (octal parts); all of these reach 192.168.0.1.
    """
    host = host.strip().strip("[]").lower()
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) > 4 or any(not p for p in parts):
        return None
    numbers: list[int] = []
    for part in parts:
        try:
            if part.startswith("0x"):
                numbers.append(int(part[2:], 16))
            elif len(part) > 1 and part.startswith("0"):
                numbers.append(int(part, 8))
            else:
                numbers.append(int(part, 10))
        except ValueError:
            return None
    # inet_aton semantics: the last part fills all remaining bytes.
    *head, last = numbers
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(value)


_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_internal_ip(ip: IPAddress) -> bool:
    """RFC 1918, CGNAT, loopback and link-local: addresses inside someone's network.

    Documentation ranges (192.0.2.0/24 and friends) deliberately count as external,
    because the synthetic samples use them to stand in for Internet hosts.
    """
    return any(ip.version == net.version and ip in net for net in _INTERNAL_NETWORKS)
