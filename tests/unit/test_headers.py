"""Received, Authentication-Results and header-text helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from app.parsing.authres import parse_authentication_results
from app.parsing.headertext import blank_comments, split_outside_quotes, unfold
from app.parsing.received import origin_ip, parse_chain, parse_received


def test_unfold_and_comments() -> None:
    assert unfold("a\r\n\tb\n c") == "a b c"
    masked = blank_comments('x (comment (nested) "q") y "(not a comment)"')
    assert masked.startswith("x ")
    assert masked[2:24].strip() == ""
    assert "(not a comment)" in masked
    assert len(masked) == len('x (comment (nested) "q") y "(not a comment)"')
    assert split_outside_quotes('a; "b;c"; d') == ["a", ' "b;c"', " d"]


def test_parse_received_typical() -> None:
    hop = parse_received(
        "from relay.evil.example (relay.evil.example [203.0.113.9])\r\n"
        "\tby mx.example.edu (Postfix) with ESMTPS id 4XyZ12\r\n"
        "\tfor <alice@example.edu>; Tue, 24 Nov 2026 08:00:01 +0000",
        0,
    )
    assert hop.from_host == "relay.evil.example"
    assert hop.from_ip == "203.0.113.9"
    assert hop.by_host == "mx.example.edu"
    assert hop.with_protocol == "ESMTPS"
    assert hop.id == "4XyZ12"
    assert hop.for_addr == "alice@example.edu"
    assert hop.timestamp == datetime(2026, 11, 24, 8, 0, 1, tzinfo=UTC)


def test_parse_received_tolerates_garbage() -> None:
    hop = parse_received("garbage without any clause; not a date", 3)
    assert hop.index == 3
    assert hop.from_host is None
    assert hop.timestamp is None
    hop = parse_received("from [IPv6:2001:db8::1] by mx.example.edu", 0)
    assert hop.from_ip == "2001:db8::1"
    assert hop.timestamp is None


def test_parse_received_date_without_zone() -> None:
    hop = parse_received("by mx.example.edu; 24 Nov 2026 08:00:01", 0)
    assert hop.timestamp is not None
    assert hop.timestamp.tzinfo is not None


def test_origin_ip_skips_internal_hops() -> None:
    hops = parse_chain(
        [
            "from internal.example.edu (internal [10.1.2.3]) by mx.example.edu",
            "from relay.evil.example ([198.51.100.20]) by edge.example.edu",
            "from laptop (unknown [192.168.1.5]) by relay.evil.example",
        ]
    )
    assert [h.index for h in hops] == [0, 1, 2]
    assert origin_ip(hops) == "198.51.100.20"
    assert origin_ip(parse_chain(["from a (a [10.0.0.1]) by b"])) is None


def test_authentication_results() -> None:
    parsed = parse_authentication_results(
        "mx.example.edu;\r\n spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.example;"
        '\r\n dkim=none; dmarc=fail reason="p=reject" header.from=example.edu'
    )
    assert parsed is not None
    assert parsed.authserv_id == "mx.example.edu"
    by_method = {r.method: r for r in parsed.results}
    assert by_method["spf"].result == "fail"
    assert by_method["spf"].properties == {"smtp.mailfrom": "evil.example"}
    assert by_method["dkim"].result == "none"
    assert by_method["dmarc"].reason == "p=reject"
    assert by_method["dmarc"].properties["header.from"] == "example.edu"


def test_authentication_results_variants() -> None:
    versioned = parse_authentication_results("MX.Example.EDU 1; dkim/1=PASS header.d=x.example")
    assert versioned is not None
    assert versioned.authserv_id == "mx.example.edu"
    assert versioned.results[0].method == "dkim"
    assert versioned.results[0].result == "pass"

    none = parse_authentication_results("mx.example.edu; none")
    assert none is not None
    assert none.results == []

    no_id = parse_authentication_results("spf=pass smtp.mailfrom=example.com")
    assert no_id is not None
    assert no_id.authserv_id == ""
    assert no_id.results[0].result == "pass"

    assert parse_authentication_results("   ") is None
    broken = parse_authentication_results("mx.example.edu; =; spf=; junk")
    assert broken is not None
    assert broken.results == []
