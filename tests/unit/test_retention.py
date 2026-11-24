"""Retention: raw messages, attachments and bodies go after RETENTION_DAYS; evidence stays."""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import pytest
from fakeredis import FakeRedis
from rq import Queue
from sqlalchemy import select

import app.jobs as jobs
from app import audit, cli, retention
from app.db.models import AuditLog, Report, ReportSource, ReportStatus
from app.ingest.submission import requeue_reports
from app.jobs import run_report
from app.pipeline import submit
from app.queueing import QUEUE_NAME, SERIALIZER
from app.web.routes.reports import can_requeue

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
PAYLOAD = b"MZ\x90\x00 shared attachment bytes"


def message(subject: str, attachment: bytes | None = PAYLOAD) -> bytes:
    msg = EmailMessage()
    msg["From"] = "Billing <billing@invoices.example>"
    msg["To"] = "alice@example.edu"
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{uuid.uuid4()}@invoices.example>"
    msg.set_content("Please see the attached invoice.\nhttps://pay.invoices.example/x\n")
    if attachment is not None:
        msg.add_attachment(
            attachment, maintype="application", subtype="octet-stream", filename="inv.exe"
        )
    return msg.as_bytes()


@pytest.fixture
def report_at(make_settings, worker_context, session_factory, store):
    """Store and analyse a message as if it had arrived ``days_ago`` days before NOW."""
    context = worker_context(make_settings())

    def make(days_ago: int, raw: bytes | None = None) -> uuid.UUID:
        with session_factory() as session:
            report = submit(
                session,
                store,
                raw or message(f"Invoice {uuid.uuid4().hex[:6]}"),
                source=ReportSource.UPLOAD,
                received_at=NOW - timedelta(days=days_ago),
            )
            session.commit()
            report_id = report.id
        assert run_report(context, report_id) is ReportStatus.DONE
        return report_id

    return make


def files(store) -> set[str]:
    root: Path = store.root
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


def purge(session_factory, store, **kwargs) -> retention.PurgeResult:
    with session_factory() as session:
        return retention.purge_expired(
            session, store, retention_days=kwargs.pop("days", 90), now=NOW, **kwargs
        )


def test_old_report_loses_content_but_keeps_its_evidence(report_at, session_factory, store) -> None:
    old = report_at(120)
    with session_factory() as session:
        before = session.get(Report, old)
        assert before is not None
        assert before.email is not None
        stored = {before.submission_path, before.email.raw_path} | {
            a.storage_path for a in before.attachments
        }
        verdict, score = before.verdict, before.score
        rules = {f.rule_id for f in before.findings}
        indicators = {(o.type, o.value) for o in before.observables}
    assert rules
    assert indicators
    assert stored <= files(store)

    result = purge(session_factory, store)

    assert (result.reports, result.files_kept) == (1, 0)
    assert result.files_deleted == len(stored - {None})
    assert files(store) == set()
    with session_factory() as session:
        after = session.get(Report, old)
        assert after is not None
        assert after.email is not None
        assert after.purged_at is not None
        assert after.submission_path is None
        assert after.email.raw_path is None
        assert after.email.body_text == ""
        assert after.email.body_html_clean is None
        assert all(a.storage_path is None for a in after.attachments)
        # Kept: verdict, rules, indicators, headers, file metadata.
        assert (after.verdict, after.score) == (verdict, score)
        assert {f.rule_id for f in after.findings} == rules
        assert {(o.type, o.value) for o in after.observables} == indicators
        assert after.email.subject.startswith("Invoice")
        assert [a.sha256 for a in after.attachments]
        [entry] = session.scalars(
            select(AuditLog).where(AuditLog.action == audit.RETENTION_PURGE)
        ).all()
        assert entry.user_id is None
        assert entry.details["reports"] == 1
        assert entry.details["retention_days"] == 90


def test_recent_reports_are_untouched(report_at, session_factory, store) -> None:
    report_at(89)
    before = files(store)
    result = purge(session_factory, store)
    assert result.reports == 0
    assert files(store) == before
    with session_factory() as session:
        assert session.scalars(select(AuditLog)).all() == []


def test_a_file_shared_with_a_newer_report_is_kept(report_at, session_factory, store) -> None:
    old = report_at(200)
    new = report_at(10)
    with session_factory() as session:
        new_report = session.get(Report, new)
        assert new_report is not None
        [shared] = [a.storage_path for a in new_report.attachments]
    result = purge(session_factory, store)
    assert (result.reports, result.files_kept) == (1, 1)
    assert shared in files(store)
    with session_factory() as session:
        old_report = session.get(Report, old)
        assert old_report is not None
        assert all(a.storage_path is None for a in old_report.attachments)

    # Once the newer report expires too, nothing refers to the file any more.
    later = purge(session_factory, store, days=5)
    assert later.reports == 1
    assert files(store) == set()


def test_shared_files_across_batches(
    report_at, session_factory, store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(retention, "BATCH_SIZE", 1)
    report_at(300)
    report_at(200)
    result = purge(session_factory, store)
    assert (result.reports, result.files_kept) == (2, 0)
    assert files(store) == set()


def test_dry_run_changes_nothing(
    report_at, session_factory, store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(retention, "BATCH_SIZE", 1)
    report_at(100, message("a", attachment=None))
    report_at(100, message("b", attachment=None))
    before = files(store)
    result = purge(session_factory, store, dry_run=True)
    assert result.reports == 2
    assert result.files_deleted == len(before)
    assert files(store) == before
    with session_factory() as session:
        assert all(r.purged_at is None for r in session.scalars(select(Report)))


def test_second_run_and_interrupted_run(report_at, session_factory, store) -> None:
    report_at(100)
    # A run that died after deleting the files but before the commit: the rows still
    # point at the files, the next run finishes the job.
    for path in files(store):
        store.delete(path)
    first = purge(session_factory, store)
    assert (first.reports, first.files_deleted) == (1, 0)
    assert purge(session_factory, store).reports == 0


def test_purge_blocks_reanalysis(report_at, session_factory, store) -> None:
    old = report_at(100)
    fresh = report_at(1)
    purge(session_factory, store)
    queued: list[uuid.UUID] = []
    with session_factory() as session:
        report = session.get(Report, old)
        assert report is not None
        assert not can_requeue(report)
        assert requeue_reports(session, queued.append, [old, fresh]) == [fresh]
    assert queued == [fresh]


def test_console_shows_the_purge(report_at, session_factory, store, app_factory, console) -> None:
    old = report_at(100)
    purge(session_factory, store)
    client = console(app_factory())
    page = client.get(f"/reports/{old}")
    assert page.status_code == 200
    assert "deleted on 2026-11-24 under the retention policy (90 days)" in page.text
    assert "Analyse again" not in page.text
    with session_factory() as session:
        report = session.get(Report, old)
        assert report is not None
        [attachment] = report.attachments
    download = client.get(f"/reports/{old}/attachments/{attachment.id}")
    assert download.status_code == 410


def test_queue_daily_purge_once_per_day() -> None:
    redis = FakeRedis()
    queued: list[int] = []
    assert retention.queue_daily_purge(redis, lambda: queued.append(1))
    assert not retention.queue_daily_purge(redis, lambda: queued.append(1))
    assert queued == [1]
    ttl = redis.ttl(retention.SCHEDULE_KEY)
    assert 0 < ttl <= 24 * 3600

    def broken() -> None:
        raise ConnectionError("queue down")

    redis.delete(retention.SCHEDULE_KEY)
    with pytest.raises(ConnectionError):
        retention.queue_daily_purge(redis, broken)
    assert not redis.exists(retention.SCHEDULE_KEY)  # the next round tries again


def test_enqueue_purge_uses_the_json_queue() -> None:
    from app.queueing import enqueue_purge

    redis = FakeRedis()
    enqueue_purge(redis)
    [job] = Queue(QUEUE_NAME, connection=redis, serializer=SERIALIZER).get_jobs()
    assert job.func_name == "app.jobs.purge_expired"


def test_purge_job(
    report_at, make_settings, worker_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    report_at(400)
    monkeypatch.setattr(jobs, "get_context", lambda: worker_context(make_settings()))
    summary = jobs.purge_expired()
    assert summary["reports"] == 1
    assert summary["files_deleted"] >= 2


def test_cli_purge(report_at, session_factory, store, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.db.session

    report_at(5000)  # long before the real "now" the CLI uses
    monkeypatch.setattr(app.db.session, "get_sessionmaker", lambda: session_factory)
    monkeypatch.setenv("STORAGE_DIR", str(store.root))
    out = io.StringIO()
    assert cli.main(["purge", "--dry-run"], out=out) == 0
    assert out.getvalue().startswith("would purge 1 report(s) received before ")
    out = io.StringIO()
    assert cli.main(["purge", "--days", "30"], out=out) == 0
    assert out.getvalue().startswith("purged 1 report(s)")
    assert files(store) == set()
