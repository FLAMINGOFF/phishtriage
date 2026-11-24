"""Authentication and sender rules: each one triggers and does not trigger."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.analyzers import auth, sender
from app.analyzers.lookalike import find_lookalike, mixed_script_label, skeleton
from app.config import Policy
from app.intel.models import IntelSnapshot
from tests.unit.analyzer_helpers import TRUSTED, message, run

CYR_A = chr(0x0430)
CYR_O = chr(0x043E)


def authres(spf: str = "pass", dkim: str = "pass", dmarc: str = "pass", by: str = TRUSTED) -> str:
    return (
        f"{by}; spf={spf} smtp.mailfrom=sender.example; dkim={dkim} header.d=sender.example;"
        f" dmarc={dmarc} header.from=sender.example"
    )


# ----------------------------------------------------------------------------- auth


def test_dmarc_fail(example_policy: Policy) -> None:
    hits = run(auth.analyze, message(auth=[authres(dmarc="fail")]), example_policy)
    assert "AUTH_DMARC_FAIL" in hits
    assert hits["AUTH_DMARC_FAIL"].evidence[0].match.startswith("dmarc=fail")
    assert "AUTH_DMARC_FAIL" not in run(auth.analyze, message(auth=[authres()]), example_policy)


def test_spf_fail_and_softfail(example_policy: Policy) -> None:
    hard = run(auth.analyze, message(auth=[authres(spf="fail")]), example_policy)
    assert hard["AUTH_SPF_FAIL"].variant is None
    soft = run(auth.analyze, message(auth=[authres(spf="softfail")]), example_policy)
    assert soft["AUTH_SPF_FAIL"].variant == "softfail"
    assert run(auth.analyze, message(auth=[authres(spf="neutral")]), example_policy) == {}


def test_dkim_fail_unless_another_signature_passes(example_policy: Policy) -> None:
    assert "AUTH_DKIM_FAIL" in run(
        auth.analyze, message(auth=[authres(dkim="fail")]), example_policy
    )
    both = f"{TRUSTED}; dkim=fail header.d=a.example; dkim=pass header.d=b.example"
    assert "AUTH_DKIM_FAIL" not in run(auth.analyze, message(auth=[both]), example_policy)


def test_forged_results_are_ignored(example_policy: Policy) -> None:
    forged = authres(spf="pass", dmarc="pass", by="mx.evil.example")
    hits = run(auth.analyze, message(auth=[forged]), example_policy)
    assert set(hits) == {"AUTH_NO_TRUSTED_RESULTS"}
    assert hits["AUTH_NO_TRUSTED_RESULTS"].evidence[0].value == "mx.evil.example"
    # A forged "fail" from someone else does not count either.
    forged_fail = authres(dmarc="fail", by="mx.evil.example")
    assert "AUTH_DMARC_FAIL" not in run(auth.analyze, message(auth=[forged_fail]), example_policy)


def test_no_results_at_all(example_policy: Policy) -> None:
    hits = run(auth.analyze, message(), example_policy)
    assert set(hits) == {"AUTH_NO_TRUSTED_RESULTS"}
    assert "AUTH_NO_TRUSTED_RESULTS" not in run(
        auth.analyze, message(auth=[authres()]), example_policy
    )


def test_topmost_trusted_header_wins(example_policy: Policy) -> None:
    raw = message(auth=[authres(), authres(dmarc="fail", spf="fail")])
    assert run(auth.analyze, raw, example_policy) == {}


def test_inline_forward_skips_auth(example_policy: Policy) -> None:
    raw = message(auth=[authres(dmarc="fail")])
    assert run(auth.analyze, raw, example_policy, inline=True) == {}


# ----------------------------------------------------------------------------- look-alikes


@pytest.mark.parametrize(
    "domain",
    [
        "examp1e.example",  # digit for letter, other TLD
        "exarnple.edu",  # rn for m
        "exmaple.edu",  # swapped letters
        f"ex{CYR_A}mple.edu",  # Cyrillic a
        f"mail.ex{CYR_A}mple.example",
    ],
)
def test_lookalike_domains(domain: str) -> None:
    assert find_lookalike(domain, ("example.edu",)) is not None


@pytest.mark.parametrize(
    "domain",
    [
        "example.edu",
        "mail.example.edu",
        "example.com",
        "example.org",
        "unrelated.example",
        "mit.example",
    ],
)
def test_not_lookalike(domain: str) -> None:
    assert find_lookalike(domain, ("example.edu",)) is None


def test_short_names_need_more_than_distance() -> None:
    assert find_lookalike("mlt.example", ("mit.edu",)) is None  # 3 letters: too short
    assert find_lookalike("mlt.edu", ("mit.edu",)) is not None  # whole domain 1 edit away


def test_skeleton_and_scripts() -> None:
    assert skeleton(f"p{CYR_A}yp{CYR_A}l") == "paypal"
    assert skeleton("PAYPAL") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert mixed_script_label(f"p{CYR_A}ypal.example") == f"p{CYR_A}ypal"
    assert mixed_script_label(f"{CYR_O}{CYR_A}.example") is None  # all Cyrillic is fine
    assert mixed_script_label("paypal.example") is None
    assert find_lookalike(f"p{CYR_A}ypal.example", ("example.edu",)) is not None


# ----------------------------------------------------------------------------- sender


def test_lookalike_sender(example_policy: Policy) -> None:
    hits = run(sender.analyze, message(from_="Alice <a@examp1e.example>"), example_policy)
    assert "SENDER_LOOKALIKE_DOMAIN" in hits
    assert "[@]" in hits["SENDER_LOOKALIKE_DOMAIN"].evidence[0].value  # defanged
    assert run(sender.analyze, message(from_="Alice <a@example.edu>"), example_policy) == {}


def test_display_name_spoof(example_policy: Policy) -> None:
    raw = message(from_="IT Service Desk <helpdesk@evil.example>")
    assert "SENDER_DISPLAY_NAME_SPOOF" in run(sender.analyze, raw, example_policy)
    raw = message(from_='"it  service DESK" <helpdesk@evil.example>')  # case and spaces
    assert "SENDER_DISPLAY_NAME_SPOOF" in run(sender.analyze, raw, example_policy)
    raw = message(from_='"alice@example.edu" <alice@evil.example>')  # our address as name
    assert "SENDER_DISPLAY_NAME_SPOOF" in run(sender.analyze, raw, example_policy)
    raw = message(from_="IT Service Desk <helpdesk@example.edu>")
    assert "SENDER_DISPLAY_NAME_SPOOF" not in run(sender.analyze, raw, example_policy)
    raw = message(from_="Alice Example <alice@evil.example>")
    assert "SENDER_DISPLAY_NAME_SPOOF" not in run(sender.analyze, raw, example_policy)


def test_freemail_impersonation(example_policy: Policy) -> None:
    raw = message(from_="Payroll Office <payroll2026@freemail.example>")
    hits = run(sender.analyze, raw, example_policy)
    assert "SENDER_FREEMAIL_IMPERSONATION" in hits
    raw = message(from_="Bob <bob@freemail.example>")
    assert "SENDER_FREEMAIL_IMPERSONATION" not in run(sender.analyze, raw, example_policy)
    raw = message(from_="Payroll Office <payroll@evil.example>")  # not free webmail
    assert "SENDER_FREEMAIL_IMPERSONATION" not in run(sender.analyze, raw, example_policy)


def test_new_domain(example_policy: Policy) -> None:
    now = datetime(2026, 11, 24, tzinfo=UTC)
    raw = message(from_="Billing <billing@fresh.example>")
    young = IntelSnapshot(domain_registered={"fresh.example": now - timedelta(days=5)})
    hits = run(sender.analyze, raw, example_policy, intel=young, now=now)
    assert "SENDER_NEW_DOMAIN" in hits
    assert "5 day(s) ago" in hits["SENDER_NEW_DOMAIN"].evidence[0].match
    old = IntelSnapshot(domain_registered={"fresh.example": now - timedelta(days=400)})
    assert "SENDER_NEW_DOMAIN" not in run(sender.analyze, raw, example_policy, intel=old, now=now)
    assert "SENDER_NEW_DOMAIN" not in run(sender.analyze, raw, example_policy, now=now)  # no RDAP
    assert "SENDER_NEW_DOMAIN" not in run(sender.analyze, raw, example_policy, intel=young)


def test_reply_to_mismatch(example_policy: Policy) -> None:
    raw = message(from_="A <a@sender.example>", reply_to="b@other.example")
    hits = run(sender.analyze, raw, example_policy)
    assert "SENDER_REPLY_TO_MISMATCH" in hits
    assert "other[.]example" in hits["SENDER_REPLY_TO_MISMATCH"].evidence[0].match
    raw = message(from_="A <a@sender.example>", reply_to="b@support.sender.example")
    assert "SENDER_REPLY_TO_MISMATCH" not in run(sender.analyze, raw, example_policy)
    assert "SENDER_REPLY_TO_MISMATCH" not in run(sender.analyze, message(), example_policy)


def test_inline_forward_and_missing_from_skip_sender(example_policy: Policy) -> None:
    raw = message(from_="IT Service Desk <helpdesk@examp1e.example>", reply_to="x@y.example")
    assert run(sender.analyze, raw, example_policy, inline=True) == {}
    no_from = b"To: a@example.edu\r\nSubject: s\r\n\r\nbody\r\n"
    assert run(sender.analyze, no_from, example_policy) == {}
