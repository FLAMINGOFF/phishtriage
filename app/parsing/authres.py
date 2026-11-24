"""Parse ``Authentication-Results`` headers (RFC 8601).

Example::

    Authentication-Results: mx.example.edu;
        spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.example;
        dkim=none; dmarc=fail (p=reject) header.from=example.edu

This module only parses. Deciding which headers to *trust* (by authserv-id) is policy
and lives in the auth analyzer: anyone can put this header into a message they send.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.parsing.headertext import blank_comments, split_outside_quotes, unfold


class MethodResult(BaseModel):
    method: str
    result: str
    reason: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)


class AuthenticationResults(BaseModel):
    authserv_id: str
    results: list[MethodResult]
    raw: str


def _parse_resinfo(text: str) -> MethodResult | None:
    tokens = text.split()
    if not tokens or "=" not in tokens[0]:
        return None
    method, _, result = tokens[0].partition("=")
    method = method.split("/", 1)[0].strip().lower()  # "dkim/1=pass" -> "dkim"
    result = result.strip().strip('"').lower()
    if not method or not result:
        return None
    info = MethodResult(method=method, result=result)
    for token in tokens[1:]:
        key, sep, value = token.partition("=")
        if not sep:
            continue
        key, value = key.lower(), value.strip('"')
        if key == "reason":
            info.reason = value
        else:
            info.properties[key] = value
    return info


def parse_authentication_results(value: str) -> AuthenticationResults | None:
    raw = unfold(value)
    segments = [s.strip() for s in split_outside_quotes(blank_comments(raw))]
    if not segments or not segments[0]:
        return None
    first = segments[0].split()
    if "=" in first[0]:
        # Non-compliant header without an authserv-id (seen from some providers).
        authserv_id, resinfo = "", segments
    else:
        authserv_id, resinfo = first[0].lower(), segments[1:]
        # "mx.example.edu 1; ..." carries a version number; "mx.example.edu; none" none.
    results = [r for r in (_parse_resinfo(seg) for seg in resinfo if seg) if r is not None]
    return AuthenticationResults(authserv_id=authserv_id, results=results, raw=raw)
