from __future__ import annotations

import pytest

from app.parsing.defang import defang, defang_email, defang_ip, defang_url, refang


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://login-example.com/a.b?x=1", "hxxps://login-example[.]com/a.b?x=1"),
        ("http://user@evil.example:8080/p", "hxxp://user[@]evil[.]example:8080/p"),
        ("ftp://files.example.net", "fxp://files[.]example[.]net"),
        ("HTTPS://Example.com", "hxxps://Example[.]com"),
        ("https://evil.example#frag.x", "hxxps://evil[.]example#frag.x"),
    ],
)
def test_defang_url(url: str, expected: str) -> None:
    assert defang_url(url) == expected
    assert refang(defang_url(url)).lower() == url.lower()


def test_defanged_url_has_no_clickable_scheme_or_dots() -> None:
    result = defang_url("https://a.b.example/path")
    assert "https://" not in result
    assert "a.b.example" not in result


def test_defang_other_types() -> None:
    assert defang_ip("192.0.2.1") == "192[.]0[.]2[.]1"
    assert defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"
    assert defang_email("a.b@mail.example.com") == "a.b[@]mail[.]example[.]com"
    assert defang("example.com", "domain") == "example[.]com"
    assert defang("ab" * 32, "sha256") == "ab" * 32


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("hxxps://evil[.]example/x", "https://evil.example/x"),
        ("evil(.)example", "evil.example"),
        ("evil[dot]example", "evil.example"),
        ("user[at]evil[.]example", "user@evil.example"),
        ("hxxp[://]a[.]b", "http://a.b"),
        ("2001[:]db8[:][:]1", "2001:db8::1"),
    ],
)
def test_refang(text: str, expected: str) -> None:
    assert refang(text) == expected


def test_defang_url_without_scheme() -> None:
    assert defang_url("evil.example/path") == "evil[.]example/path"
    assert defang_url("mailto://x.example") == "mailto://x[.]example"
