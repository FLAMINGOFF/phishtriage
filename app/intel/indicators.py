"""Checks that an indicator is safe to put into a provider's URL path."""

from __future__ import annotations

import re

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Lower-case ASCII host name (punycode for IDNs), at least two labels.
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def is_sha256(value: str) -> bool:
    return bool(_SHA256.match(value))


def is_domain(value: str) -> bool:
    return bool(_DOMAIN.match(value))


def tld(domain: str) -> str:
    return domain.rsplit(".", 1)[-1]
