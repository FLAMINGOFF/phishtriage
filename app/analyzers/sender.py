"""Sender analyzer: who the email claims to be from, and whether that adds up."""

from __future__ import annotations

import re
import unicodedata
from datetime import timedelta

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.analyzers.lookalike import find_lookalike
from app.config import Policy
from app.parsing.defang import defang_domain, defang_email
from app.parsing.domains import is_subdomain_or_same, registered_domain

NEW_DOMAIN_DAYS = 30
_ADDRESS_IN_NAME = re.compile(r"[^\s<>\"'@]+@([^\s<>\"'@]+\.[^\s<>\"'@]+)")


def normalise_name(text: str) -> str:
    """Case-, width- and whitespace-insensitive form for comparing display names."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _is_internal(domain: str, policy: Policy) -> bool:
    return any(
        is_subdomain_or_same(domain, own)
        for own in (*policy.org_domains, *policy.protected_domains)
    )


def _claimed_names(display_name: str, policy: Policy) -> list[str]:
    shown = normalise_name(display_name)
    return [name for name in policy.protected_names if normalise_name(name) in shown]


def analyze(ctx: AnalysisContext) -> list[Hit]:
    email, policy = ctx.email, ctx.policy
    if email.forwarded_inline or email.from_addr is None:
        return []
    sender = email.from_addr
    domain = sender.domain
    if not domain:
        return []
    reg = registered_domain(domain)
    internal = _is_internal(domain, policy)
    hits: list[Hit] = []

    lookalike = None if internal else find_lookalike(domain, policy.protected_domains)
    if lookalike is not None:
        hits.append(
            hit(
                "SENDER_LOOKALIKE_DOMAIN",
                [evidence("From", sender.address, lookalike.reason, kind="email")],
            )
        )

    claimed = _claimed_names(sender.display_name, policy)
    if not internal:
        items = [
            evidence("From (display name)", sender.display_name, f"contains '{name}'")
            for name in claimed
        ]
        for match in _ADDRESS_IN_NAME.finditer(sender.display_name):
            if _is_internal(match.group(1).lower(), policy):
                items.append(
                    evidence(
                        "From (display name)",
                        sender.display_name,
                        f"shows our address {defang_email(match.group(0))}",
                    )
                )
        if items:
            items.append(evidence("From (address)", sender.address, "external", kind="email"))
            hits.append(hit("SENDER_DISPLAY_NAME_SPOOF", items))

    if claimed and reg in {registered_domain(d) for d in policy.freemail_domains}:
        hits.append(
            hit(
                "SENDER_FREEMAIL_IMPERSONATION",
                [
                    evidence("From (display name)", sender.display_name, f"claims '{claimed[0]}'"),
                    evidence(
                        "From (address)",
                        sender.address,
                        f"free webmail ({defang_domain(reg)})",
                        kind="email",
                    ),
                ],
            )
        )

    registered_at = ctx.intel.domain_registered.get(reg)
    if registered_at is not None and ctx.now is not None:
        age = ctx.now - registered_at
        if timedelta(0) <= age < timedelta(days=NEW_DOMAIN_DAYS):
            hits.append(
                hit(
                    "SENDER_NEW_DOMAIN",
                    [
                        evidence(
                            "From (domain)",
                            reg,
                            f"registered {registered_at.date().isoformat()}, {age.days} day(s) ago",
                            kind="domain",
                        )
                    ],
                )
            )

    mismatched: list[Evidence] = [
        evidence(
            "Reply-To",
            reply.address,
            f"domain {defang_domain(registered_domain(reply.domain))} differs from "
            f"From domain {defang_domain(reg)}",
            kind="email",
        )
        for reply in email.reply_to
        if reply.domain and registered_domain(reply.domain) != reg
    ]
    if mismatched:
        hits.append(hit("SENDER_REPLY_TO_MISMATCH", mismatched))
    return hits
