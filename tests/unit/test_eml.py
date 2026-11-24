"""Message parsing: limits, charsets, malformed input and intake modes."""

from __future__ import annotations

from collections.abc import Callable
from email.message import EmailMessage

import pytest

from app.parsing.eml import (
    Limits,
    MessageRejected,
    extract_originals,
    looks_forwarded_inline,
    parse_message,
)

Loader = Callable[[str], bytes]


def simple(subject: str = "Hello", body: str = "Body text", **headers: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = headers.pop("from_", "Sender <sender@example.com>")
    msg["To"] = "alice@example.edu"
    msg["Subject"] = subject
    msg["Message-ID"] = "<m1@example.com>"
    msg["Date"] = "Tue, 24 Nov 2026 08:00:00 +0000"
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    msg.set_content(body)
    return msg


def test_parse_simple_message() -> None:
    parsed, embedded = parse_message(bytes(simple(Reply_To="other@example.net")))
    assert embedded == []
    assert parsed.subject == "Hello"
    assert parsed.message_id == "<m1@example.com>"
    assert parsed.from_addr is not None
    assert parsed.from_addr.address == "sender@example.com"
    assert parsed.from_addr.display_name == "Sender"
    assert parsed.from_addr.domain == "example.com"
    assert [a.address for a in parsed.reply_to] == ["other@example.net"]
    assert parsed.sent_at is not None
    assert parsed.body_text.strip() == "Body text"
    assert parsed.body_html is None
    assert ("Subject", "Hello") in parsed.headers
    assert parsed.size == len(bytes(simple(Reply_To="other@example.net")))


def test_rejects_oversize_message() -> None:
    raw = bytes(simple(body="x" * 2000))
    with pytest.raises(MessageRejected, match="limit is 1,000 bytes"):
        parse_message(raw, Limits(max_bytes=1000))


def test_rejects_too_many_attachments() -> None:
    msg = simple()
    for i in range(4):
        msg.add_attachment(b"data", maintype="application", subtype="pdf", filename=f"{i}.pdf")
    parse_message(bytes(msg), Limits(max_attachments=4))
    msg.add_attachment(b"data", maintype="application", subtype="pdf", filename="x.pdf")
    with pytest.raises(MessageRejected, match="5 attachments, the limit is 4"):
        parse_message(bytes(msg), Limits(max_attachments=4))


def test_rejects_deep_nesting() -> None:
    depth = 12
    boundaries = [f"b{i}" for i in range(depth)]
    lines = ["From: a@example.com", "Subject: deep", "MIME-Version: 1.0"]
    lines.append(f'Content-Type: multipart/mixed; boundary="{boundaries[0]}"')
    lines.append("")
    for i in range(1, depth):
        header = f'Content-Type: multipart/mixed; boundary="{boundaries[i]}"'
        lines += [f"--{boundaries[i - 1]}", header, ""]
    lines += [f"--{boundaries[-1]}", "Content-Type: text/plain", "", "core"]
    for b in reversed(boundaries):
        lines.append(f"--{b}--")
    raw = "\r\n".join(lines).encode()
    with pytest.raises(MessageRejected, match="nest"):
        parse_message(raw)
    parsed, _ = parse_message(raw, Limits(max_depth=20))
    assert parsed.body_text == "core"


@pytest.mark.parametrize("raw", [b"", b"\x00\x01\x02 binary junk", b"just one line of text"])
def test_rejects_non_email(raw: bytes) -> None:
    with pytest.raises(MessageRejected):
        parse_message(raw)


def test_garbage_bytes_in_headers_do_not_crash() -> None:
    raw = (
        b"From: =?utf-8?b?!!!?= <bad@@example..com>, \xff\xfe\r\n"
        b"Subject: =?unknown-charset?q?x?= \xc3\x28\r\n"
        b"Date: not a date\r\n"
        b"Content-Type: text/plain; charset=x-unknown\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"!!!not base64!!!\r\n"
    )
    parsed, _ = parse_message(raw)
    assert parsed.sent_at is None
    assert isinstance(parsed.subject, str)
    assert isinstance(parsed.body_text, str)


@pytest.mark.parametrize(
    ("charset", "text"),
    [
        ("gb2312", "\u4f60\u597d\uff0c\u9555"),  # GBK-only character under a gb2312 label
        ("gbk", "\u8f6c\u8d26\u901a\u77e5"),
        ("big5", "\u5e33\u865f\u9a57\u8b49"),
        ("iso-2022-jp", "\u30d1\u30b9\u30ef\u30fc\u30c9"),
        ("windows-1252", "caf\u00e9 \u20ac"),
        ("utf-8", "\u2713 ok"),
    ],
)
def test_body_charsets(charset: str, text: str) -> None:
    encoded = text.encode("gb18030" if charset == "gb2312" else charset)
    raw = (
        b"From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=" + charset.encode() + b"\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\n" + encoded
    )
    parsed, _ = parse_message(raw)
    assert parsed.body_text == text


def test_html_only_message_gets_text() -> None:
    msg = simple()
    msg.set_content("<p>Pay <a href='https://pay.example/'>now</a></p>", subtype="html")
    parsed, _ = parse_message(bytes(msg))
    assert parsed.body_html is not None
    assert parsed.body_text == "Pay now"


def test_filename_control_characters_are_removed() -> None:
    raw = (
        b"From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        b"--b\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=utf-8''a%0D%0Ab%00.exe\r\n\r\nMZ\r\n"
        b"--b--\r\n"
    )
    parsed, _ = parse_message(raw)
    assert parsed.attachments[0].filename == "ab.exe"


def test_embedded_message_is_returned_not_descended() -> None:
    inner = simple(subject="Inner", body="secret original")
    outer = simple(subject="Report")
    outer.add_attachment(inner)
    parsed, embedded = parse_message(bytes(outer))
    assert len(embedded) == 1
    assert b"secret original" in embedded[0]
    assert "secret original" not in parsed.body_text
    assert parsed.attachments[0].declared_type == "message/rfc822"


def test_intake_modes(fixture_bytes: Loader) -> None:
    attached = extract_originals(fixture_bytes("06"), is_report_wrapper=True)
    assert attached.mode == "attachment"
    assert [o.subject for o in attached.originals] == ["Overdue invoice #20261124"]
    assert not attached.originals[0].forwarded_inline

    two = extract_originals(fixture_bytes("08"), is_report_wrapper=True)
    assert two.mode == "attachment"
    assert len(two.originals) == 2

    octet = extract_originals(fixture_bytes("13"), is_report_wrapper=True)
    assert octet.mode == "attachment"
    assert octet.originals[0].from_addr is not None

    inline = extract_originals(fixture_bytes("07"), is_report_wrapper=True)
    assert inline.mode == "inline"
    assert inline.originals[0].forwarded_inline
    assert not inline.outer.forwarded_inline

    direct = extract_originals(fixture_bytes("01"), is_report_wrapper=False)
    assert direct.mode == "direct"
    assert direct.originals[0] is direct.outer


def test_upload_of_a_forward_is_inline(fixture_bytes: Loader) -> None:
    intake = extract_originals(fixture_bytes("07"), is_report_wrapper=False)
    assert intake.mode == "inline"


def test_forward_heuristics() -> None:
    assert looks_forwarded_inline(parse_message(bytes(simple(subject="Fwd: hi")))[0])
    assert looks_forwarded_inline(parse_message(bytes(simple(subject="FW: hi")))[0])
    assert looks_forwarded_inline(
        parse_message(bytes(simple(subject="\u8f6c\u53d1\uff1a\u901a\u77e5")))[0]
    )
    body = "see below\n\n---------- Forwarded message ---------\nFrom: x"
    assert looks_forwarded_inline(parse_message(bytes(simple(body=body)))[0])
    assert not looks_forwarded_inline(parse_message(bytes(simple(subject="Forward plan")))[0])


def test_malformed_fixture(fixture_bytes: Loader) -> None:
    parsed, _ = parse_message(fixture_bytes("05"))
    assert parsed.defects  # recorded, not fatal
    assert parsed.from_addr is not None


def test_attachments_zoo(fixture_bytes: Loader) -> None:
    parsed, embedded = parse_message(fixture_bytes("09"))
    assert embedded == []
    names = [a.filename for a in parsed.attachments]
    assert "statement.pdf" in names
    assert any("\u202e" in name for name in names)  # RTLO kept: it is the evidence
