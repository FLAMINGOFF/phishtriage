#!/usr/bin/env python3
"""Report sample emails to the PhishTriage report mailbox, like an employee would.

Each sample is sent as its own report: an email from the reporter to the report mailbox
with the sample attached as ``message/rfc822`` ("Forward as attachment"), or with
``--inline`` pasted into the body ("Forward"). Then, with ``--wait``, it watches Mailpit
for PhishTriage's reply to each report.

    python3 scripts/send_sample.py                       # every file in samples/
    python3 scripts/send_sample.py samples/credential-phish.eml --wait 60
    python3 scripts/send_sample.py --from outsider@external.example   # gets no reply

Defaults match the Compose demo: GreenMail SMTP on 127.0.0.1:3025, Mailpit on
http://127.0.0.1:8025. The script adds the ``Authentication-Results`` header that the
organisation's mail server would add (``mx.example.edu; ... dmarc=pass``): the demo
mailbox has no real mail server in front of it. Standard library only.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import json
import smtplib
import sys
import time
import urllib.error
import urllib.request
from email.utils import formatdate, make_msgid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
FORWARD_TEXT = "Hi,\r\n\r\nI received the attached email and I think it may be phishing.\r\n"


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower()


def _crlf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def _sample_subject_and_text(raw: bytes) -> tuple[str, str]:
    """Subject and body text for the report, tolerant of the broken samples (bad charsets)."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    try:
        subject = str(message.get("Subject", "") or "")
    except (ValueError, LookupError):
        subject = ""
    body = message.get_body(preferencelist=("plain", "html"))
    if body is None:
        return subject, ""
    try:
        text = body.get_content()
    except (LookupError, UnicodeError, KeyError):
        payload = body.get_payload(decode=True)
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""
    return subject, text


def build_report(
    sample: bytes,
    *,
    reporter: str,
    mailbox: str,
    authserv_id: str | None,
    inline: bool,
) -> tuple[str, bytes]:
    """The report email (Message-ID, raw bytes). Built by hand so the sample stays intact."""
    subject, text = _sample_subject_and_text(sample)
    message_id = make_msgid("report", domain=_domain(reporter))
    domain = _domain(reporter)
    headers = []
    if authserv_id:
        headers.append(
            f"Authentication-Results: {authserv_id}; spf=pass smtp.mailfrom={domain};"
            f" dkim=pass header.d={domain}; dmarc=pass header.from={domain}"
        )
    clean_subject = " ".join(subject.split())[:150]
    headers += [
        f"From: {reporter}",
        f"To: {mailbox}",
        f"Subject: Fwd: {clean_subject}" if clean_subject else "Subject: Fwd: suspicious email",
        f"Date: {formatdate(localtime=False)}",
        f"Message-ID: {message_id}",
        "MIME-Version: 1.0",
    ]
    if inline:
        body = (
            FORWARD_TEXT + "\r\n---------- Forwarded message ---------\r\n"
            f"Subject: {clean_subject}\r\n\r\n" + text.replace("\n", "\r\n")
        )
        headers += ["Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit"]
        return message_id, ("\r\n".join(headers) + "\r\n\r\n" + body).encode("utf-8")
    boundary = "=_report_" + message_id.strip("<>").split("@")[0].replace(".", "_")
    headers.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
    parts = [
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{FORWARD_TEXT}".encode(),
        (
            f"--{boundary}\r\nContent-Type: message/rfc822\r\n"
            'Content-Disposition: attachment; filename="suspicious-email.eml"\r\n\r\n'
        ).encode()
        + _crlf(sample).rstrip(b"\r\n")
        + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    return message_id, ("\r\n".join(headers) + "\r\n\r\n").encode() + b"".join(parts)


def send(host: str, port: int, sender: str, recipient: str, data: bytes) -> None:
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.sendmail(sender, [recipient], data)


def _get_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - our Mailpit URL
        return json.load(response)


def find_replies(mailpit: str, wanted: set[str], seen: dict[str, str | None]) -> dict[str, str]:
    """Mailpit messages that answer one of ``wanted`` (Message-IDs): {Message-ID: subject}."""
    found: dict[str, str] = {}
    listing = _get_json(f"{mailpit}/api/v1/messages?limit=200")
    for summary in listing.get("messages", []) if isinstance(listing, dict) else []:
        mailpit_id = summary.get("ID")
        if not mailpit_id:
            continue
        if mailpit_id not in seen:
            headers = _get_json(f"{mailpit}/api/v1/message/{mailpit_id}/headers")
            values = headers.get("In-Reply-To", []) if isinstance(headers, dict) else []
            seen[mailpit_id] = values[0] if values else None
        answered = seen[mailpit_id]
        if answered in wanted:
            found[answered] = summary.get("Subject", "")
    return found


def wait_for_replies(mailpit: str, sent: dict[str, str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    seen: dict[str, str | None] = {}
    pending = set(sent)
    while pending:
        try:
            for message_id, subject in find_replies(mailpit, pending, seen).items():
                print(f"reply for {sent[message_id]}: {subject}")
                pending.discard(message_id)
        except (OSError, urllib.error.URLError, ValueError) as exc:
            print(f"Mailpit not reachable yet: {exc}", file=sys.stderr)
        if not pending:
            break
        if time.monotonic() > deadline:
            for message_id in sorted(pending):
                print(f"no reply for {sent[message_id]} within {timeout:.0f} s", file=sys.stderr)
            return False
        time.sleep(2)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", type=Path, help="sample .eml files (default: samples/)")
    parser.add_argument("--from", dest="reporter", default="alice@example.edu")
    parser.add_argument("--to", dest="mailbox", default="report-phishing@example.edu")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=3025)
    parser.add_argument("--inline", action="store_true", help="forward inline, not attached")
    parser.add_argument(
        "--authserv-id",
        default="mx.example.edu",
        help="authserv-id of the Authentication-Results header to add ('' for none)",
    )
    parser.add_argument("--wait", type=float, metavar="SECONDS", help="wait for the replies")
    parser.add_argument("--mailpit", default="http://127.0.0.1:8025")
    parser.add_argument("--json", action="store_true", help="print what was sent as JSON")
    args = parser.parse_args(argv)

    files = args.files or sorted(SAMPLES.glob("*.eml"))
    if not files:
        print("no sample files", file=sys.stderr)
        return 2
    sent: dict[str, str] = {}
    for path in files:
        message_id, data = build_report(
            path.read_bytes(),
            reporter=args.reporter,
            mailbox=args.mailbox,
            authserv_id=args.authserv_id or None,
            inline=args.inline,
        )
        send(args.smtp_host, args.smtp_port, args.reporter, args.mailbox, data)
        sent[message_id] = path.name
        if not args.json:
            print(f"sent {path.name} as {message_id}")
    if args.json:
        print(json.dumps([{"file": f, "message_id": m} for m, f in sent.items()]))
    if args.wait is not None:
        return 0 if wait_for_replies(args.mailpit.rstrip("/"), sent, args.wait) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
