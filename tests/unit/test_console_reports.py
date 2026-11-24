"""Analyst console: report queue, detail page, verdicts, notes, re-analysis, downloads."""

from __future__ import annotations

import hashlib
import io
import re
import uuid
import zipfile
from collections.abc import Callable
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import audit
from app.db.models import (
    Attachment,
    AuditLog,
    Report,
    ReportSource,
    ReportStatus,
    Verdict,
    utcnow,
)
from app.web.routes.reports import BODY_CSP
from tests.unit.console_helpers import csrf

Loader = Callable[[str], bytes]

HOSTILE = b"""\
From: "<img src=x onerror=alert(1)>" <attacker@evil.example>
To: victim@example.edu
Subject: <script>alert(2)</script>
Message-ID: <hostile@evil.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=utf-8

</pre><script>alert(3)</script> plain
--inner
Content-Type: text/html; charset=utf-8

<p onclick="alert(4)">Hello</p><script>alert(5)</script>
<a href="https://evil.example/login">Sign in</a><img src="https://evil.example/pixel.gif">
--inner--
--outer
Content-Type: application/pdf
Content-Disposition: attachment; filename="<svg onload=alert(6)>.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrp/Og0MTGCg==
--outer--
""".replace(b"\n", b"\r\n")


@pytest.fixture
def client(app_factory: Callable[..., FastAPI], console) -> TestClient:
    return console(app_factory())


def upload(client: TestClient, content: bytes) -> uuid.UUID:
    response = client.post(
        "/upload",
        files={"file": ("x.eml", content)},
        data={"csrf_token": csrf(client, "/upload")},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return uuid.UUID(response.headers["location"].rsplit("/", 1)[1])


def post(client: TestClient, path: str, **data: str):
    return client.post(
        path, data={**data, "csrf_token": csrf(client, "/upload")}, follow_redirects=False
    )


def entries(session_factory, action: str) -> list[AuditLog]:
    with session_factory() as session:
        return list(session.scalars(select(AuditLog).where(AuditLog.action == action)))


# --------------------------------------------------------------------------- queue


def test_queue_filters(client: TestClient, fixture_bytes: Loader) -> None:
    phish = upload(client, fixture_bytes("02"))
    benign = upload(client, fixture_bytes("11"))
    page = client.get("/reports").text
    assert "2 reports." in page
    assert "Mailbox quota exceeded" in page
    assert "Library opening hours" in page

    page = client.get("/reports", params={"verdict": "malicious"}).text
    assert "Mailbox quota exceeded" in page
    assert "Library opening hours" not in page
    page = client.get("/reports", params={"verdict": "no_issues"}).text
    assert "Mailbox quota exceeded" not in page
    assert "Library opening hours" in page
    page = client.get("/reports", params={"status": "failed"}).text
    assert "No reports match this filter" in page
    page = client.get("/reports", params={"verdict": "none"}).text
    assert "No reports match this filter" in page

    # The analyst's verdict wins in the filter and the list.
    assert post(client, f"/reports/{benign}/verdict", verdict="suspicious").status_code == 303
    page = client.get("/reports", params={"verdict": "suspicious"}).text
    assert "Library opening hours" in page
    assert "analyst</small>" in page
    assert "Library opening hours" not in client.get("/reports?verdict=no_issues").text
    page = client.get("/reports", params={"reviewed": "yes"}).text
    assert "Library opening hours" in page
    assert "Mailbox quota exceeded" not in page
    page = client.get("/reports", params={"reviewed": "no"}).text
    assert "Library opening hours" not in page
    assert "Mailbox quota exceeded" in page

    # Sorting: by score puts the phish first, oldest first puts it first too.
    page = client.get("/reports", params={"sort": "score"}).text
    assert page.index(str(phish)) < page.index(str(benign))
    page = client.get("/reports", params={"sort": "oldest"}).text
    assert page.index(str(phish)) < page.index(str(benign))
    page = client.get("/reports").text  # newest first
    assert page.index(str(benign)) < page.index(str(phish))

    # Unknown values are ignored instead of failing.
    page = client.get("/reports", params={"verdict": "x", "status": "y", "sort": "z"})
    assert page.status_code == 200
    assert "2 reports." in page.text


def test_queue_pagination(client: TestClient, session_factory) -> None:
    start = utcnow()
    with session_factory() as session:
        for n in range(120):
            session.add(
                Report(
                    source=ReportSource.API,
                    received_at=start - timedelta(minutes=n),
                    status=ReportStatus.FAILED,
                    error="rejected: test",
                    submission_sha256=f"{n:064x}",
                    submission_size=1,
                )
            )
        session.commit()
    rows = re.compile(r'<a href="/reports/[0-9a-f-]{36}">')
    first = client.get("/reports", params={"status": "failed"}).text
    assert "120 reports" in first
    assert len(rows.findall(first)) == 50
    assert "Page 1 of 3" in first
    assert 'href="/reports?status=failed&amp;page=2"' in first
    last = client.get("/reports", params={"status": "failed", "page": 3}).text
    assert len(rows.findall(last)) == 20
    clamped = client.get("/reports", params={"status": "failed", "page": 99}).text
    assert "Page 3 of 3" in clamped
    assert client.get("/reports", params={"page": 0}).status_code == 422


# --------------------------------------------------------------------------- detail page


def test_detail_page_sections(client: TestClient, fixture_bytes: Loader) -> None:
    report_id = upload(client, fixture_bytes("02"))
    page = client.get(f"/reports/{report_id}").text
    for heading in (
        "Review",
        "Summary",
        "Why",
        "Indicators",
        "Attachments",
        "Authentication results",
        "Received chain",
        "Body",
        "Activity",
    ):
        assert f"<h2>{heading}</h2>" in page, heading
    assert "All headers (" in page
    assert "Malicious" in page
    assert "automatic, score" in page
    assert "AUTH_DMARC_FAIL" in page
    assert "[.]" in page  # indicators defanged
    assert 'class="badge badge-no_issues">trusted</span>' in page  # mx.example.edu is trusted
    assert f'action="/reports/{report_id}/verdict"' in page
    assert f'href="/reports/{report_id}/iocs.stix.json"' in page
    assert f'action="/reports/{report_id}/requeue"' in page
    # Uploading was recorded and shows in the activity.
    assert "Uploaded from the console" in page


def test_hostile_content_is_escaped(client: TestClient, fixture_bytes: Loader) -> None:
    """M4 acceptance: XSS in subject, display name, file name and body is shown as text."""
    report_id = upload(client, HOSTILE)
    page = client.get(f"/reports/{report_id}").text
    body = page.split("</head>", 1)[1]
    for raw in ("<script>alert", "<img src=x", "<svg onload", "onclick=", "</pre><script"):
        assert raw not in body, raw
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in body  # subject
    assert "&lt;img src=x onerror=alert(1)&gt;" in body  # display name
    assert "&lt;svg onload=alert(6)&gt;.pdf" in body  # attachment file name
    assert "&lt;/pre&gt;&lt;script&gt;alert(3)&lt;/script&gt;" in body  # text body
    assert 'iframe class="email-html" sandbox ' in body  # the HTML body is sandboxed

    queue = client.get("/reports").text.split("</head>", 1)[1]
    assert "<script>alert" not in queue
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in queue

    html = client.get(f"/reports/{report_id}/body")
    assert html.status_code == 200
    assert html.headers["content-security-policy"] == BODY_CSP
    assert "sandbox" in html.headers["content-security-policy"]
    assert html.headers["x-frame-options"] == "SAMEORIGIN"
    for raw in ("<script", "onclick", "href=", "src=", "evil.example"):
        assert raw not in html.text, raw
    assert "Hello" in html.text
    assert "Sign in" in html.text

    # The note field is hostile input too.
    post(client, f"/reports/{report_id}/notes", text="<script>alert(7)</script>")
    page = client.get(f"/reports/{report_id}").text
    assert "<script>alert(7)" not in page
    assert "&lt;script&gt;alert(7)&lt;/script&gt;" in page


def test_text_only_email_has_no_html_body(client: TestClient, fixture_bytes: Loader) -> None:
    report_id = upload(client, fixture_bytes("11"))
    assert client.get(f"/reports/{report_id}/body").status_code == 404
    assert "email-html" not in client.get(f"/reports/{report_id}").text
    assert client.get(f"/reports/{uuid.uuid4()}/body").status_code == 404


# --------------------------------------------------------------------------- verdicts and notes


def test_reclassify_keeps_the_score(
    client: TestClient, fixture_bytes: Loader, session_factory
) -> None:
    report_id = upload(client, fixture_bytes("02"))
    with session_factory() as session:
        before = session.get(Report, report_id)
        assert before is not None
        score, automatic = before.score, before.verdict
    assert automatic is Verdict.MALICIOUS

    response = post(client, f"/reports/{report_id}/verdict", verdict="no_issues")
    assert response.status_code == 303
    assert response.headers["location"] == f"/reports/{report_id}#review"
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report is not None
        assert report.analyst_verdict is Verdict.NO_ISSUES
        assert report.final_verdict is Verdict.NO_ISSUES
        assert (report.score, report.verdict) == (score, automatic)  # original kept
        assert report.closed_at is not None
    [entry] = entries(session_factory, audit.REPORT_RECLASSIFY)
    assert entry.report_id == report_id
    assert entry.details == {"verdict": "no_issues", "automatic": "malicious", "score": score}
    page = client.get(f"/reports/{report_id}").text
    assert "set by an analyst" in page
    assert "Verdict set to <strong>No issues found</strong>" in page

    # Saving the same verdict again changes nothing and logs nothing.
    post(client, f"/reports/{report_id}/verdict", verdict="no_issues")
    assert len(entries(session_factory, audit.REPORT_RECLASSIFY)) == 1

    # Back to the automatic verdict: the report is open again.
    post(client, f"/reports/{report_id}/verdict", verdict="")
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report is not None
        assert (report.analyst_verdict, report.closed_at) == (None, None)
    assert entries(session_factory, audit.REPORT_RECLASSIFY)[-1].details["previous"] == (
        "no_issues"
    )

    assert post(client, f"/reports/{report_id}/verdict", verdict="harmless").status_code == 422
    assert post(client, f"/reports/{uuid.uuid4()}/verdict", verdict="malicious").status_code == 404


def test_reclassify_needs_a_finished_report(
    app_factory: Callable[..., FastAPI], console, fixture_bytes: Loader
) -> None:
    client = console(app_factory(enqueue=lambda _id: None))  # the worker never runs
    report_id = upload(client, fixture_bytes("02"))
    assert post(client, f"/reports/{report_id}/verdict", verdict="malicious").status_code == 409
    page = client.get(f"/reports/{report_id}").text
    assert "/verdict" not in page  # no form while it is still queued
    assert "/requeue" not in page


def test_notes(client: TestClient, fixture_bytes: Loader, session_factory) -> None:
    report_id = upload(client, fixture_bytes("11"))
    response = post(client, f"/reports/{report_id}/notes", text="  Called the sender.\nLegit.  ")
    assert response.status_code == 303
    assert response.headers["location"] == f"/reports/{report_id}#activity"
    [note] = entries(session_factory, audit.REPORT_NOTE)
    assert note.details == {"text": "Called the sender.\nLegit."}
    assert note.user_id is not None
    page = client.get(f"/reports/{report_id}").text
    assert '<span class="note">Called the sender.\nLegit.</span>' in page
    assert "analyst@example.edu" in page.split('id="activity"', 1)[1]

    assert post(client, f"/reports/{report_id}/notes", text="   ").status_code == 422
    assert post(client, f"/reports/{report_id}/notes", text="x" * 2001).status_code == 422


# --------------------------------------------------------------------------- re-analysis


def test_requeue(client: TestClient, fixture_bytes: Loader, session_factory) -> None:
    report_id = upload(client, fixture_bytes("02"))
    response = post(client, f"/reports/{report_id}/requeue")
    assert response.status_code == 303
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report is not None
        assert report.status is ReportStatus.DONE  # the test queue runs the job at once
        assert report.verdict is Verdict.MALICIOUS
    assert len(entries(session_factory, audit.REPORT_REQUEUE)) == 1

    # A submission split into several reports is re-analysed with the CLI only.
    parent = upload(client, fixture_bytes("08"))
    with session_factory() as session:
        child = session.scalar(select(Report.id).where(Report.parent_id == parent))
    assert "/requeue" not in client.get(f"/reports/{parent}").text
    assert post(client, f"/reports/{parent}/requeue").status_code == 409
    assert post(client, f"/reports/{child}/requeue").status_code == 409


def test_requeue_with_queue_down(
    app_factory: Callable[..., FastAPI], console, fixture_bytes: Loader, session_factory
) -> None:
    from app.queueing import QueueUnavailable

    calls: list[object] = []

    def flaky(report_id: object) -> None:
        calls.append(report_id)
        if len(calls) > 1:
            raise QueueUnavailable("down")

    client = console(app_factory(enqueue=flaky))
    report_id = upload(client, fixture_bytes("11"))
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report is not None
        report.status = ReportStatus.FAILED
        session.commit()
    assert post(client, f"/reports/{report_id}/requeue").status_code == 503


# --------------------------------------------------------------------------- attachments


def test_attachment_download_is_an_encrypted_zip(
    client: TestClient, fixture_bytes: Loader, session_factory, store
) -> None:
    report_id = upload(client, fixture_bytes("09"))
    with session_factory() as session:
        attachments = list(
            session.scalars(select(Attachment).where(Attachment.report_id == report_id))
        )
    by_name = {a.filename: a for a in attachments}
    rlo = by_name["photo‮gpj.exe"]
    page = client.get(f"/reports/{report_id}").text
    assert f'href="/reports/{report_id}/attachments/{rlo.id}"' in page
    assert "<code>infected</code>" in page

    response = client.get(f"/reports/{report_id}/attachments/{rlo.id}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="attachment-{rlo.sha256[:16]}.zip"'
    )
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        [info] = archive.infolist()
        assert info.filename == "photogpj.exe"  # the right-to-left override is gone
        assert info.flag_bits & 0x1  # encrypted
        with pytest.raises(RuntimeError, match="password"):
            archive.read(info)
        content = archive.read(info, pwd=b"infected")
    assert hashlib.sha256(content).hexdigest() == rlo.sha256

    [entry] = entries(session_factory, audit.ATTACHMENT_DOWNLOAD)
    assert entry.report_id == report_id
    assert entry.details["sha256"] == rlo.sha256
    assert entry.details["filename"] == "photogpj.exe"

    # Another report's ID, an unknown ID, and a file removed by retention.
    assert client.get(f"/reports/{uuid.uuid4()}/attachments/{rlo.id}").status_code == 404
    assert client.get(f"/reports/{report_id}/attachments/{uuid.uuid4()}").status_code == 404
    other = by_name["statement.pdf"]
    assert other.storage_path is not None
    store.delete(other.storage_path)
    assert client.get(f"/reports/{report_id}/attachments/{other.id}").status_code == 410
    with session_factory() as session:
        stored = session.get(Attachment, other.id)
        assert stored is not None
        stored.storage_path = None
        session.commit()
    assert client.get(f"/reports/{report_id}/attachments/{other.id}").status_code == 410
    assert ">deleted</span>" in client.get(f"/reports/{report_id}").text
