from __future__ import annotations

import ipaddress

import pytest

from app.parsing.domains import (
    is_internal_ip,
    is_subdomain_or_same,
    parse_ip,
    registered_domain,
    to_ascii,
    to_unicode,
)

CYRILLIC_A = chr(0x0430)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("3232235777", "192.168.1.1"),  # decimal
        ("0xc0a80001", "192.168.0.1"),  # hex
        ("0300.0250.0.1", "192.168.0.1"),  # octal parts
        ("127.1", "127.0.0.1"),  # short form
        ("192.0.2.1", "192.0.2.1"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_parse_ip_accepts_browser_forms(host: str, expected: str) -> None:
    assert str(parse_ip(host)) == expected


@pytest.mark.parametrize("host", ["example.com", "1.2.3.4.5", "256.1.1.1", "08.1.1.1", "", "1..2"])
def test_parse_ip_rejects(host: str) -> None:
    assert parse_ip(host) is None


def test_to_ascii_and_back() -> None:
    homoglyph = f"ex{CYRILLIC_A}mple.edu"
    ascii_form = to_ascii(homoglyph)
    assert ascii_form.startswith("xn--")
    assert to_unicode(ascii_form) == homoglyph
    assert to_ascii("Example.COM.") == "example.com"


def test_to_ascii_survives_invalid_idna() -> None:
    assert to_ascii("bad\u2028host.example") != ""


def test_registered_domain() -> None:
    assert registered_domain("login.mail.example.co.uk") == "example.co.uk"
    assert registered_domain("Login.Evil.Example") == "evil.example"  # reserved TLD
    assert registered_domain("192.0.2.1") == "192.0.2.1"
    assert registered_domain("localhost") == "localhost"


def test_subdomain_check() -> None:
    assert is_subdomain_or_same("mail.example.edu", "example.edu")
    assert is_subdomain_or_same("example.edu", "example.edu")
    assert not is_subdomain_or_same("badexample.edu", "example.edu")


def test_internal_ip() -> None:
    assert is_internal_ip(ipaddress.ip_address("10.1.2.3"))
    assert is_internal_ip(ipaddress.ip_address("fe80::1"))
    assert not is_internal_ip(ipaddress.ip_address("203.0.113.9"))
    assert not is_internal_ip(ipaddress.ip_address("2001:db8::1"))
