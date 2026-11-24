"""IOC extraction: URLs, hosts, addresses, IPs and hashes."""

from __future__ import annotations

from collections.abc import Callable
from email.message import EmailMessage

import pytest

from app.parsing.eml import parse_message
from app.parsing.iocs import (
    MAX_OBSERVABLES,
    extract_observables,
    find_urls,
    mailto_addresses,
    normalize_url,
)

Loader = Callable[[str], bytes]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("visit https://evil.example/login.", ["https://evil.example/login"]),
        ("(see http://a.example/x)", ["http://a.example/x"]),
        ("wiki https://w.example/A_(b) ok", ["https://w.example/A_(b)"]),
        ("www.example.com/path, then", ["http://www.example.com/path"]),
        ("HTTPS://EVIL.Example:8443/A?b=1#c", ["https://evil.example:8443/A?b=1#c"]),
        ("ftp://files.example/x.zip", ["ftp://files.example/x.zip"]),
        ("javascript:alert(1) data:text/html,x", []),
        ("<https://quoted.example/>", ["https://quoted.example/"]),
    ],
)
def test_find_urls(text: str, expected: list[str]) -> None:
    assert find_urls(text) == expected


def test_normalize_url() -> None:
    assert normalize_url("https://xn--80ak6aa92e.com/") == "https://xn--80ak6aa92e.com/"
    assert normalize_url("https://" + chr(0x0430) + "pple.example/") == (
        "https://xn--pple-43d.example/"
    )
    assert normalize_url("http://3405803786/x") == "http://3405803786/x"  # kept as written
    assert normalize_url("http://[2001:db8::1]:8080/") == "http://[2001:db8::1]:8080/"
    assert normalize_url("http://user@evil.example/") == "http://user@evil.example/"
    assert normalize_url("http://[broken/") is None
    assert normalize_url("http://host.example:99999/") is None
    assert normalize_url("mailto:a@example.com") is None
    assert normalize_url("https:///nohost") is None


def test_find_urls_is_linear_on_hostile_input() -> None:
    text = "http://" + "a" * 100_000 + " " + "www." * 50_000
    urls = find_urls(text)
    assert all(len(u) <= 2100 for u in urls)


def _message(html: str | None = None, text: str = "", **headers: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = headers.get("from_", "Payroll <payroll@freemail.example>")
    msg["To"] = "alice@example.edu"
    msg["Subject"] = "s"
    if "reply_to" in headers:
        msg["Reply-To"] = headers["reply_to"]
    msg.set_content(text or "see attached")
    if html is not None:
        msg.add_alternative(html, subtype="html")
    return msg


def test_extract_observables_covers_all_kinds() -> None:
    msg = _message(
        html=(
            '<a href="https://login.evil.example/a">https://www.example.edu/</a>'
            '<a href="https://www.example.edu/help">help</a>'
            '<a href="mailto:Drop@Collect.Example?subject=x">mail</a>'
            '<img src="http://198.51.100.7/p.gif">'
        ),
        text="Also http://0xC0000201/x and www.second.example",
        reply_to="reply@reply.test",
    )
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="a.exe")
    msg["Received"] = "from x (x [203.0.113.5]) by mx.example.edu; 24 Nov 2026 08:00:00 +0000"
    parsed, _ = parse_message(bytes(msg))
    observables = {(o.type, o.value) for o in extract_observables(parsed, ["example.edu"])}

    assert ("url", "https://login.evil.example/a") in observables
    assert ("domain", "login.evil.example") in observables
    assert ("url", "http://0xc0000201/x") in observables
    assert ("ip", "192.0.2.1") in observables  # hex IP decoded
    assert ("ip", "198.51.100.7") in observables
    assert ("ip", "203.0.113.5") in observables  # origin IP from Received
    assert ("url", "http://www.second.example") in observables
    assert ("email", "payroll@freemail.example") in observables
    assert ("domain", "freemail.example") in observables
    assert ("email", "reply@reply.test") in observables
    assert ("email", "drop@collect.example") in observables
    assert any(kind == "sha256" for kind, _ in observables)
    # Our own domain is not an indicator.
    assert not any("example.edu" in value for _, value in observables)


def test_inline_forward_skips_reporter_addresses(fixture_bytes: Loader) -> None:
    from app.parsing.eml import extract_originals

    intake = extract_originals(fixture_bytes("07"), is_report_wrapper=True)
    observables = extract_observables(intake.originals[0], ["example.edu"])
    assert not any(o.type == "email" for o in observables)
    assert any(o.type == "url" for o in observables)


def test_observables_are_capped() -> None:
    text = " ".join(f"https://h{i}.example/" for i in range(MAX_OBSERVABLES))
    parsed, _ = parse_message(bytes(_message(text=text)))
    assert len(extract_observables(parsed)) == MAX_OBSERVABLES


def test_defanged_values() -> None:
    parsed, _ = parse_message(bytes(_message(text="go to https://login-example.com/x")))
    defanged = {o.value: o.defanged for o in extract_observables(parsed)}
    assert defanged["https://login-example.com/x"] == "hxxps://login-example[.]com/x"
    assert defanged["login-example.com"] == "login-example[.]com"


def test_mailto_without_html() -> None:
    parsed, _ = parse_message(bytes(_message(text="plain")))
    assert mailto_addresses(parsed) == []
