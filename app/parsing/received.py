"""Parse ``Received`` headers into a hop chain.

The format (RFC 5321 section 4.4) is loose and every MTA writes it differently, so the
parser is tolerant: it extracts what it recognises and keeps the raw header for the
analyst. Hops are numbered from the top, i.e. hop 0 was added last (by our own server).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from pydantic import BaseModel

from app.parsing.domains import is_internal_ip, parse_ip
from app.parsing.headertext import blank_comments, unfold

_CLAUSE = re.compile(r"(?i)(?:^|\s)(from|by|via|with|id|for)\s+")
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{2,45})\]")
_BARE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


class ReceivedHop(BaseModel):
    index: int
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_protocol: str | None = None
    id: str | None = None
    for_addr: str | None = None
    timestamp: datetime | None = None
    raw: str


def _first_token(text: str) -> str | None:
    token = text.strip().split(" ", 1)[0].strip("<>;,") if text.strip() else ""
    return token or None


def _find_ip(text: str) -> str | None:
    for pattern in (_BRACKET_IP, _BARE_IPV4):
        for match in pattern.finditer(text):
            ip = parse_ip(match.group(1))
            if ip is not None:
                return str(ip)
    return None


def _parse_date(text: str) -> datetime | None:
    try:
        value = parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def parse_received(value: str, index: int) -> ReceivedHop:
    raw = unfold(value)
    head, sep, date_part = raw.rpartition(";")
    if not sep:
        head, date_part = raw, ""
    masked = blank_comments(head)

    clauses: dict[str, tuple[str, str]] = {}  # keyword -> (masked text, original text)
    matches = list(_CLAUSE.finditer(masked))
    for i, match in enumerate(matches):
        keyword = match.group(1).lower()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(masked)
        if keyword not in clauses:  # the first occurrence wins
            clauses[keyword] = (masked[match.end() : end], head[match.end() : end])

    hop = ReceivedHop(index=index, raw=raw, timestamp=_parse_date(date_part) if date_part else None)
    if "from" in clauses:
        masked_text, original = clauses["from"]
        hop.from_host = _first_token(masked_text)
        # The IP usually sits in a comment: "from mx.example (mx.example [192.0.2.1])".
        hop.from_ip = _find_ip(original)
    if "by" in clauses:
        hop.by_host = _first_token(clauses["by"][0])
    if "with" in clauses:
        hop.with_protocol = _first_token(clauses["with"][0])
    if "id" in clauses:
        hop.id = _first_token(clauses["id"][0])
    if "for" in clauses:
        hop.for_addr = _first_token(clauses["for"][0])
    return hop


def parse_chain(values: list[str]) -> list[ReceivedHop]:
    return [parse_received(value, i) for i, value in enumerate(values)]


def origin_ip(hops: list[ReceivedHop]) -> str | None:
    """The earliest external IP in the chain: where the message entered the Internet.

    Headers below our own server's hop can be forged by the sender, so this is a hint
    for the analyst, not evidence on its own.
    """
    for hop in reversed(hops):
        if hop.from_ip:
            ip = parse_ip(hop.from_ip)
            if ip is not None and not is_internal_ip(ip):
                return hop.from_ip
    return None
