"""Replies to reporters: who gets one, what it says, how it is sent."""

from __future__ import annotations

import uuid
from email.message import EmailMessage
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.db.models import Report, ReportSource, ReportStatus
from app.ingest.imap_poller import message_id
from app.ingest.submission import queue_submission
from app.jobs import run_report
from app.notify import reply
from app.notify.reply import clean_subject, is_org_address, reporter_dmarc
from app.parsing.eml import extract_originals
from scripts.send_sample import build_report

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"
REPORTER = "alice@example.edu"


class FakeSMTP:
    """Stands in for smtplib.SMTP and SMTP_SSL."""

    sent: ClassVar[list[EmailMessage]] = []
    connections: ClassVar[list[FakeSMTP]] = []
    error: ClassVar[Exception | None] = None

    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host, self.port, self.kwargs = host, port, kwargs
        self.calls: list[str] = []
        FakeSMTP.connections.append(self)

    def __enter__(self) -> FakeSMTP:
        if FakeSMTP.error is not None:
            raise FakeSMTP.error
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append("quit")

    def starttls(self, context: object = None) -> None:
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(f"login {user} {password}")

    def send_message(self, message: EmailMessage) -> None:
        FakeSMTP.sent.append(message)


class FakeSMTPSSL(FakeSMTP):
    pass


@pytest.fixture(autouse=True)
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.sent, FakeSMTP.connections, FakeSMTP.error = [], [], None
    monkeypatch.setattr(reply.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(reply.smtplib, "SMTP_SSL", FakeSMTPSSL)
    return FakeSMTP


@pytest.fixture
def mailbox(make_settings, worker_context, session_factory, store):
    """Deliver a report to the mailbox and run the worker on it: returns the report."""

    def deliver(
        sample: str | bytes = "credential-phish.eml",
        *,
        reporter: str = REPORTER,
        authserv_id: str | None = "mx.example.edu",
        inline: bool = False,
        **overrides,
    ) -> Report:
        content = sample if isinstance(sample, bytes) else (SAMPLES / sample).read_bytes()
        _, raw = build_report(
            content,
            reporter=reporter,
            mailbox="report-phishing@example.edu",
            authserv_id=authserv_id,
            inline=inline,
        )
        context = worker_context(make_settings(**overrides))
        with session_factory() as session:
            report = queue_submission(
                session,
                store,
                lambda _id: None,
                raw,
                source=ReportSource.IMAP,
                outer_message_id=message_id(raw),
            )
        run_report(context, report.id)
        with session_factory() as session:
            stored = session.get(Report, report.id)
            assert stored is not None
            return stored

    return deliver


# --------------------------------------------------------------------------- who gets a reply


def test_internal_verified_reporter_gets_the_verdict(mailbox, smtp) -> None:
    report = mailbox()
    assert report.status is ReportStatus.DONE
    assert (report.reporter_email, report.reporter_dmarc) == (REPORTER, "pass")
    assert report.reply_status == "sent"
    assert report.replied_at is not None
    [message] = smtp.sent
    assert message["To"] == REPORTER
    assert message["From"] == "PhishTriage <report-phishing@example.edu>"
    assert message["Subject"] == "[PhishTriage] Malicious: Action required: verify your account"
    assert message["In-Reply-To"] == report.outer_message_id
    assert message["References"] == report.outer_message_id
    assert message["Auto-Submitted"] == "auto-replied"
    assert message["Message-ID"].endswith("@example.edu>")
    body = message.get_content()
    assert "Result: Malicious (score" in body
    assert "Please delete it" in body
    assert "What we found:" in body
    assert "The sender's domain imitates one of our domains." in body
    assert f"Reference: {report.id}" in body
    assert "Tip: next time" not in body
    connection = smtp.connections[0]
    assert (connection.host, connection.port) == ("localhost", 1025)
    assert connection.calls == ["quit"]  # no STARTTLS, no login in the default (demo) setup


@pytest.mark.parametrize("sample", sorted(p.name for p in SAMPLES.glob("*.eml")))
def test_replies_never_call_an_email_safe(mailbox, smtp, sample: str) -> None:
    mailbox(sample)
    [message] = smtp.sent
    assert "safe" not in message.get_content().lower()
    assert "safe" not in message["Subject"].lower()


def test_no_issues_reply(mailbox, smtp) -> None:
    mailbox("benign-internal.eml")
    [message] = smtp.sent
    assert message["Subject"].startswith("[PhishTriage] No issues found: ")
    assert "does not prove the email is genuine" in message.get_content()


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"reporter": "outsider@external.example"}, "not sent: reporter outside the organisation"),
        (
            {"reporter": "alice@example.edu.evil.example"},
            "not sent: reporter outside the organisation",
        ),
        ({"authserv_id": None}, "not sent: reporter address not confirmed by DMARC"),
        (
            {"authserv_id": "mx.attacker.example"},
            "not sent: reporter address not confirmed by DMARC",
        ),
        ({"replies_enabled": False}, "not sent: replies are disabled"),
    ],
)
def test_no_reply(mailbox, smtp, kwargs, status: str) -> None:
    report = mailbox(**kwargs)
    assert report.status is ReportStatus.DONE  # analysed and stored all the same
    assert report.reply_status == status
    assert report.replied_at is None
    assert smtp.sent == []


def test_subdomain_of_the_organisation_counts(mailbox, smtp, example_policy) -> None:
    assert mailbox(reporter="bob@cs.example.edu").reply_status == "sent"
    assert is_org_address("x@EXAMPLE.edu", example_policy)
    assert not is_org_address("x@notexample.edu", example_policy)


def test_hourly_limit_per_reporter(mailbox, smtp) -> None:
    statuses = [mailbox(reply_hourly_limit=2).reply_status for _ in range(3)]
    assert statuses == ["sent", "sent", "not sent: hourly reply limit reached"]
    assert mailbox(reporter="bob@example.edu", reply_hourly_limit=2).reply_status == "sent"


def test_reanalysis_sends_no_second_reply(
    mailbox, smtp, make_settings, worker_context, session_factory
) -> None:
    report = mailbox()
    run_report(worker_context(make_settings()), report.id)
    assert len(smtp.sent) == 1
    with session_factory() as session:
        again = session.get(Report, report.id)
        assert again is not None
        assert again.reply_status == "sent"


def test_smtp_failure_is_recorded_not_fatal(mailbox, smtp) -> None:
    smtp.error = ConnectionRefusedError("mailpit is down")
    report = mailbox()
    assert report.status is ReportStatus.DONE
    assert report.reply_status == "failed: ConnectionRefusedError"
    assert report.replied_at is None


def test_unexpected_reply_error_does_not_fail_the_job(mailbox, smtp, monkeypatch) -> None:
    def broken(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("template bug")

    monkeypatch.setattr("app.jobs.notify_reporter", broken)
    report = mailbox()
    assert report.status is ReportStatus.DONE


def test_inline_forward_gets_the_hint(mailbox, smtp) -> None:
    report = mailbox(inline=True)
    assert report.intake_mode == "inline"
    [message] = smtp.sent
    assert "please forward suspicious emails as an attachment" in message.get_content()


def test_one_reply_for_a_split_submission(
    smtp, make_settings, worker_context, session_factory, store
) -> None:
    sample = (SAMPLES / "benign-internal.eml").read_bytes()
    phish = (SAMPLES / "credential-phish.eml").read_bytes()
    _, first = build_report(
        sample,
        reporter=REPORTER,
        mailbox="r@example.edu",
        authserv_id="mx.example.edu",
        inline=False,
    )
    # A second original attached to the same report.
    boundary = first.split(b'boundary="', 1)[1].split(b'"', 1)[0]
    extra = b"--" + boundary + b"\r\nContent-Type: message/rfc822\r\n\r\n" + phish + b"\r\n"
    raw = first.replace(b"--" + boundary + b"--", extra + b"--" + boundary + b"--")
    with session_factory() as session:
        report = queue_submission(
            session,
            store,
            lambda _id: None,
            raw,
            source=ReportSource.IMAP,
            outer_message_id=message_id(raw),
        )
    run_report(worker_context(make_settings()), report.id)
    [message] = smtp.sent
    body = message.get_content()
    assert message["Subject"].startswith("[PhishTriage] Malicious: ")  # the worst verdict
    assert body.count("Reported email:") == 2
    with session_factory() as session:
        children = session.scalars(select(Report).where(Report.parent_id == report.id)).all()
        assert [c.reply_status for c in children] == [None]  # the first report replied


def test_uploads_and_api_reports_get_no_reply(
    smtp, make_settings, worker_context, session_factory, store
) -> None:
    raw = (SAMPLES / "credential-phish.eml").read_bytes()
    for source in (ReportSource.UPLOAD, ReportSource.API):
        with session_factory() as session:
            report = queue_submission(
                session, store, lambda _id: None, raw, source=source, reporter_email=REPORTER
            )
        run_report(worker_context(make_settings()), report.id)
        with session_factory() as session:
            stored = session.get(Report, report.id)
            assert stored is not None
            assert stored.reply_status is None
    assert smtp.sent == []


# --------------------------------------------------------------------------- building blocks


def _outer(auth: str | None, sender: str = REPORTER):
    headers = f"From: {sender}\r\nTo: r@example.edu\r\nSubject: x\r\n"
    if auth:
        headers = f"Authentication-Results: {auth}\r\n" + headers
    raw = (headers + "\r\nhello\r\n").encode()
    return extract_originals(raw, is_report_wrapper=True).outer


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ("mx.example.edu; dmarc=pass header.from=example.edu", "pass"),
        ("MX.EXAMPLE.EDU; dmarc=pass", "pass"),  # authserv-id is case-insensitive
        ("mx.example.edu; dmarc=fail (p=reject) header.from=example.edu", "fail"),
        ("mx.example.edu; dmarc=pass header.from=other.example", None),
        ("mx.example.edu; spf=pass smtp.mailfrom=example.edu", None),
        ("evil.example; dmarc=pass header.from=example.edu", None),
        (None, None),
    ],
)
def test_reporter_dmarc(example_policy, auth: str | None, expected: str | None) -> None:
    assert reporter_dmarc(_outer(auth), example_policy) == expected


def test_reporter_dmarc_uses_the_topmost_trusted_header(example_policy) -> None:
    raw = (
        "Authentication-Results: mx.example.edu; dmarc=fail header.from=example.edu\r\n"
        "Authentication-Results: mx.example.edu; dmarc=pass header.from=example.edu\r\n"
        f"From: {REPORTER}\r\nSubject: x\r\n\r\nhi\r\n"
    ).encode()
    outer = extract_originals(raw, is_report_wrapper=True).outer
    assert reporter_dmarc(outer, example_policy) == "fail"


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("Invoice 42", "Invoice 42"),
        (None, "(no subject)"),
        ("   ", "(no subject)"),
        (
            "Log in at https://login.evil.example/x now",
            "Log in at hxxps://login[.]evil[.]example/x now",
        ),
        ("visit evil.example today", "visit evil[.]example today"),
        ("a\r\nBcc: victim@example.edu", "a Bcc: victim@example[.]edu"),
        ("photo‮gpj.exe", "photogpj[.]exe"),
        ("x" * 150, "x" * 99 + "…"),
    ],
)
def test_clean_subject(subject: str | None, expected: str) -> None:
    assert clean_subject(subject) == expected


def test_smtp_ssl_and_starttls(make_settings, smtp) -> None:
    message = EmailMessage()
    message["To"] = REPORTER
    message.set_content("x")
    reply.smtp_send(make_settings(smtp_security="ssl", smtp_port=465), message)
    assert isinstance(smtp.connections[-1], FakeSMTPSSL)
    assert smtp.connections[-1].kwargs["context"].check_hostname
    reply.smtp_send(
        make_settings(smtp_security="starttls", smtp_user="relay", smtp_password="pw"), message
    )
    assert smtp.connections[-1].calls == ["starttls", "login relay pw", "quit"]
    assert len(smtp.sent) == 2


def test_reply_settings(make_settings) -> None:
    assert make_settings(reply_from="SOC <soc@example.edu>").reply_from == "SOC <soc@example.edu>"
    for bad in ("not an address", "SOC <soc@example.edu>\r\nBcc: x@example.com"):
        with pytest.raises(ValidationError, match="REPLY_FROM"):
            make_settings(reply_from=bad)
    with pytest.raises(ValidationError, match="SMTP_SECURITY must be starttls or ssl"):
        make_settings(
            app_env="prod", secret_key="s" * 40, imap_ssl=True, smtp_user="relay", smtp_password="x"
        )


def test_decide_ignores_reports_without_mailbox_source(session_factory, make_settings) -> None:
    report = Report(
        id=uuid.uuid4(), source=ReportSource.API, submission_sha256="0" * 64, submission_size=1
    )
    with session_factory() as session:
        decision = reply.decide(session, report, make_settings())
    assert (decision.send, decision.status) == (False, None)
