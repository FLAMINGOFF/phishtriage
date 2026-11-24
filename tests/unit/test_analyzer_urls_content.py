"""Link and content rules: each one triggers and does not trigger."""

from __future__ import annotations

import pytest

from app.analyzers import content, urls
from app.config import Policy
from app.intel.models import IntelResult, IntelSnapshot
from tests.unit.analyzer_helpers import message, run

# ----------------------------------------------------------------------------- urls


def test_url_intel(example_policy: Policy) -> None:
    raw = message(text="Go to https://bad.example/login now")
    url = "https://bad.example/login"

    def snapshot(*results: IntelResult) -> IntelSnapshot:
        return IntelSnapshot(urls={url: results})

    vt = IntelResult(provider="virustotal", status="hit", malicious_count=5)
    hits = run(urls.analyze, raw, example_policy, intel=snapshot(vt))
    assert "URL_INTEL_MALICIOUS" in hits
    assert hits["URL_INTEL_MALICIOUS"].evidence[0].value == "hxxps://bad[.]example/login"
    urlhaus = IntelResult(provider="urlhaus", status="hit")
    assert "URL_INTEL_MALICIOUS" in run(urls.analyze, raw, example_policy, intel=snapshot(urlhaus))
    for harmless in (
        IntelResult(provider="virustotal", status="hit", malicious_count=2),  # below 3
        IntelResult(provider="virustotal", status="clean", malicious_count=0),
        IntelResult(provider="urlhaus", status="not_found"),
        IntelResult(provider="virustotal", status="error"),
    ):
        intel = snapshot(harmless)
        assert "URL_INTEL_MALICIOUS" not in run(urls.analyze, raw, example_policy, intel=intel)
    assert "URL_INTEL_MALICIOUS" not in run(urls.analyze, raw, example_policy)


def test_credential_form(example_policy: Policy) -> None:
    form = '<form action="https://c.example/p"><input name="u"></form>'
    assert "URL_CREDENTIAL_FORM" in run(urls.analyze, message(html=form), example_policy)
    password = '<p>Password: <input type="password"></p>'
    assert "URL_CREDENTIAL_FORM" in run(urls.analyze, message(html=password), example_policy)
    plain = "<p>Hello <b>there</b></p>"
    assert "URL_CREDENTIAL_FORM" not in run(urls.analyze, message(html=plain), example_policy)
    assert "URL_CREDENTIAL_FORM" not in run(urls.analyze, message(), example_policy)


@pytest.mark.parametrize(
    ("anchor", "expected"),
    [
        ('<a href="https://login.evil.example/">https://www.example.edu/</a>', True),
        ('<a href="https://login.evil.example/">www.example.edu</a>', True),
        ('<a href="http://198.51.100.7/">portal.example.edu</a>', True),
        ('<a href="https://www.example.org/n">www.example.org</a>', False),
        ('<a href="https://login.example.edu/">example.edu</a>', False),  # same domain
        ('<a href="https://evil.example/">Click here</a>', False),
        ('<a href="https://evil.example/">Version 2.0 notes</a>', False),  # not a host
        ('<a href="mailto:x@evil.example">help@example.edu</a>', False),  # not a web link
    ],
)
def test_text_href_mismatch(example_policy: Policy, anchor: str, expected: bool) -> None:
    hits = run(urls.analyze, message(html=f"<p>{anchor}</p>"), example_policy)
    assert ("URL_TEXT_HREF_MISMATCH" in hits) is expected


def test_ip_host(example_policy: Policy) -> None:
    for text in ("http://203.0.113.5/x", "http://3405803786/pay", "http://[2001:db8::5]/"):
        assert "URL_IP_HOST" in run(urls.analyze, message(text=text), example_policy), text
    assert "URL_IP_HOST" not in run(
        urls.analyze, message(text="https://www.example.org/203.0.113.5"), example_policy
    )


def test_punycode(example_policy: Policy) -> None:
    raw = message(text="https://xn--pple-43d.example/login")
    assert "URL_PUNYCODE" in run(urls.analyze, raw, example_policy)
    unicode_host = message(text="https://" + chr(0x0430) + "pple.example/login")
    assert "URL_PUNYCODE" in run(urls.analyze, unicode_host, example_policy)
    assert "URL_PUNYCODE" not in run(
        urls.analyze, message(text="https://apple.example/"), example_policy
    )


def test_shortener(example_policy: Policy) -> None:
    assert "URL_SHORTENER" in run(
        urls.analyze, message(text="https://short.example/x1"), example_policy
    )
    assert "URL_SHORTENER" not in run(
        urls.analyze, message(text="https://www.example.org/short.example"), example_policy
    )


def test_clean_links_raise_nothing(example_policy: Policy) -> None:
    raw = message(
        text="Notes: https://www.example.org/news",
        html='<a href="https://www.example.org/">Read</a>',
    )
    assert run(urls.analyze, raw, example_policy) == {}


# ----------------------------------------------------------------------------- content


@pytest.mark.parametrize(
    "text",
    [
        "Please verify your password at the portal.",
        "Confirm\nyour password within the next hour.",  # wrapped plain text
        "Reply with the verification code we sent you.",
        "Enter your MFA code to continue.",
        "Sign in to keep your mailbox active.",
        "Open the file and sign in with your email password.",
        "Verify your account now.",
        "请在下方输入密码以继续使用邮箱。",
        "请确认您的账户信息。",
    ],
)
def test_credential_request(example_policy: Policy, text: str) -> None:
    hits = run(content.analyze, message(text=text), example_policy)
    assert "CONTENT_CREDENTIAL_REQUEST" in hits, text


@pytest.mark.parametrize(
    "text",
    [
        "We will never ask for your password by email.",
        "Never share your verification code with anyone.",
        "Your password was changed yesterday. If this was you, no action is needed.",
        "Confirm your attendance.\n\nThe password policy is on the intranet.",  # new paragraph
        "IT 部门不会要求您提供密码。",
        "The library opens at nine.",
    ],
)
def test_no_credential_request(example_policy: Policy, text: str) -> None:
    hits = run(content.analyze, message(text=text), example_policy)
    assert "CONTENT_CREDENTIAL_REQUEST" not in hits, text


def test_urgency_counts_once(example_policy: Policy) -> None:
    raw = message(
        subject="URGENT: final notice",
        text="Your account will be suspended within 24 hours. Act immediately.",
    )
    hits = run(content.analyze, raw, example_policy)
    assert "CONTENT_URGENCY" in hits
    assert len(hits["CONTENT_URGENCY"].evidence) >= 3  # many phrases, one hit
    assert "CONTENT_URGENCY" in run(
        content.analyze, message(text="您的邮箱将被停用。"), example_policy
    )
    assert "CONTENT_URGENCY" in run(
        content.analyze, message(text="Your parcel is on hold."), example_policy
    )


def test_no_urgency(example_policy: Policy) -> None:
    raw = message(subject="November digest", text="Read the latest research news.")
    assert run(content.analyze, raw, example_policy) == {}


def test_html_text_is_read_and_snippets_are_defanged(example_policy: Policy) -> None:
    raw = message(
        text="See the HTML version.",
        html="<p>Verify your password at https://login.evil.example/now</p>",
    )
    hits = run(content.analyze, raw, example_policy)
    snippet = hits["CONTENT_CREDENTIAL_REQUEST"].evidence[0].value
    assert "hxxps://login[.]evil[.]example/now" in snippet
    assert "https://" not in snippet
