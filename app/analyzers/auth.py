"""Authentication analyzer: SPF, DKIM and DMARC as seen by *our* mail server.

Only ``Authentication-Results`` headers whose authserv-id is in
``policy.trusted_authserv_ids`` count. Anyone can write such a header into a message
they send ("spf=pass, dmarc=pass"), so all others are ignored and listed as evidence.
The topmost trusted header wins: it was added last, by the server closest to us.
"""

from __future__ import annotations

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.parsing.authres import AuthenticationResults, MethodResult


def _trusted(ctx: AnalysisContext) -> tuple[AuthenticationResults | None, list[str]]:
    trusted_ids = set(ctx.policy.trusted_authserv_ids)
    ignored: list[str] = []
    for header in ctx.email.authentication_results:
        if header.authserv_id in trusted_ids:
            return header, ignored
        ignored.append(header.authserv_id or "(no authserv-id)")
    return None, ignored


def _describe(result: MethodResult) -> str:
    props = " ".join(f"{k}={v}" for k, v in result.properties.items())
    return f"{result.method}={result.result}" + (f" {props}" if props else "")


def _item(header: AuthenticationResults, result: MethodResult) -> Evidence:
    return evidence("Authentication-Results", header.raw, _describe(result))


def analyze(ctx: AnalysisContext) -> list[Hit]:
    if ctx.email.forwarded_inline:
        return []  # the headers we have are the reporter's, not the attacker's
    header, ignored = _trusted(ctx)
    if header is None:
        items = [
            evidence("Authentication-Results", authserv_id, "authserv-id not trusted")
            for authserv_id in ignored
        ] or [evidence("Authentication-Results", "(none)", "no header from a trusted server")]
        return [hit("AUTH_NO_TRUSTED_RESULTS", items)]

    by_method: dict[str, list[MethodResult]] = {}
    for result in header.results:
        by_method.setdefault(result.method, []).append(result)
    hits: list[Hit] = []

    dmarc_fail = [r for r in by_method.get("dmarc", []) if r.result == "fail"]
    if dmarc_fail:
        hits.append(hit("AUTH_DMARC_FAIL", [_item(header, r) for r in dmarc_fail]))

    spf = by_method.get("spf", [])
    if spf_fail := [r for r in spf if r.result == "fail"]:
        hits.append(hit("AUTH_SPF_FAIL", [_item(header, r) for r in spf_fail]))
    elif spf_soft := [r for r in spf if r.result == "softfail"]:
        hits.append(hit("AUTH_SPF_FAIL", [_item(header, r) for r in spf_soft], variant="softfail"))

    # One good signature is enough for DKIM; a failed extra signature is common and benign.
    dkim = by_method.get("dkim", [])
    dkim_fail = [r for r in dkim if r.result == "fail"]
    if dkim_fail and not any(r.result == "pass" for r in dkim):
        hits.append(hit("AUTH_DKIM_FAIL", [_item(header, r) for r in dkim_fail]))
    return hits
