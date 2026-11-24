"""The worker side: jobs, retries, failure handling, re-queueing, and intel stored with reports.

M3 acceptance: without keys the pipeline runs end to end; with mocked providers the
results are stored correctly (and a provider hit forces a malicious verdict).
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
import zlib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import httpx
import pytest
import respx
from fakeredis import FakeRedis
from rq import SimpleWorker
from rq.job import Job, JobStatus
from rq.registry import ScheduledJobRegistry
from sqlalchemy import func, select

import app.jobs as jobs
from app import cli, queueing
from app.db.models import (
    IntelResultRecord,
    Observable,
    Report,
    ReportSource,
    ReportStatus,
    Verdict,
)
from app.ingest.submission import requeue_reports
from app.intel import urlhaus, virustotal
from app.pipeline import submit

PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << >>\n%%EOF\n"


def phish(sender_domain: str = "evil-login.com") -> bytes:
    msg = EmailMessage()
    msg["From"] = f'"IT Service Desk" <helpdesk@{sender_domain}>'
    msg["To"] = "alice@example.edu"
    msg["Subject"] = "Password expiry"
    msg["Message-ID"] = "<expiry-1@evil-login.com>"
    msg.set_content(f"Keep your account: http://{sender_domain}/reset\n")
    msg.add_attachment(PDF, maintype="application", subtype="pdf", filename="notice.pdf")
    return msg.as_bytes()


def stored(session_factory, store, raw: bytes) -> uuid.UUID:
    with session_factory() as session:
        report = submit(session, store, raw, source=ReportSource.UPLOAD)
        session.commit()
        return report.id


def intel_rows(session, report_id: uuid.UUID) -> dict[tuple[str, str, str], IntelResultRecord]:
    rows = session.execute(
        select(Observable, IntelResultRecord)
        .join(IntelResultRecord, IntelResultRecord.observable_id == Observable.id)
        .where(Observable.report_id == report_id)
    ).all()
    return {(o.type.value, o.value, r.provider.value): r for o, r in rows}


# --------------------------------------------------------------------------- acceptance


def test_pipeline_runs_end_to_end_without_keys(
    make_settings, worker_context, session_factory, store, http_mock: respx.Router
) -> None:
    report_id = stored(session_factory, store, phish("evil.example"))
    status = jobs.run_report(worker_context(make_settings()), report_id)
    assert status is ReportStatus.DONE
    assert not http_mock.calls
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report.verdict is not None
        assert report.error is None
        sha = report.attachments[0].sha256
        rows = intel_rows(session, report_id)
    statuses = {key: (row.status.value, row.detail) for key, row in rows.items()}
    assert statuses[("sha256", sha, "virustotal")] == ("skipped", "VT_API_KEY not set")
    assert statuses[("url", "http://evil.example/reset", "urlhaus")] == (
        "skipped",
        "URLHAUS_AUTH_KEY not set",
    )
    assert statuses[("domain", "evil.example", "rdap")] == (
        "skipped",
        "no RDAP server configured for .example",
    )
    assert all(row.fetched_at is not None for row in rows.values())


def test_mocked_providers_are_stored_and_force_malicious(
    make_settings, worker_context, session_factory, store, http_mock: respx.Router
) -> None:
    attachment_sha = hashlib.sha256(PDF).hexdigest()
    registered = (datetime.now(UTC) - timedelta(days=3)).replace(microsecond=0)
    http_mock.get(f"{virustotal.BASE_URL}/files/{attachment_sha}").respond(
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "undetected": 58}}}}
    )
    http_mock.get(url__startswith=f"{virustotal.BASE_URL}/urls/").respond(
        json={"data": {"attributes": {"last_analysis_stats": {"harmless": 70}}}}
    )
    http_mock.get(f"{virustotal.BASE_URL}/domains/evil-login.com").respond(404)
    http_mock.post(f"{urlhaus.BASE_URL}/url/").respond(
        json={"query_status": "ok", "url_status": "online", "threat": "malware_download"}
    )
    http_mock.post(f"{urlhaus.BASE_URL}/host/").respond(json={"query_status": "no_results"})
    http_mock.get("https://rdap.verisign.com/com/v1/domain/evil-login.com").respond(
        json={"events": [{"eventAction": "registration", "eventDate": registered.isoformat()}]}
    )
    settings = make_settings(
        vt_api_key="vt-test-key", urlhaus_auth_key="uh-test-key", vt_rate_per_minute=6000
    )
    report_id = stored(session_factory, store, phish())
    assert jobs.run_report(worker_context(settings), report_id) is ReportStatus.DONE

    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report.verdict is Verdict.MALICIOUS
        rule_ids = {f.rule_id for f in report.findings}
        assert {"ATT_INTEL_MALICIOUS", "URL_INTEL_MALICIOUS", "SENDER_NEW_DOMAIN"} <= rule_ids
        rows = intel_rows(session, report_id)

    vt_file = rows[("sha256", attachment_sha, "virustotal")]
    assert (vt_file.status.value, vt_file.malicious_count) == ("hit", 12)
    assert vt_file.raw == {"last_analysis_stats": {"malicious": 12, "undetected": 58}}
    assert vt_file.fetched_at is not None
    assert rows[("url", "http://evil-login.com/reset", "virustotal")].status.value == "clean"
    url_hit = rows[("url", "http://evil-login.com/reset", "urlhaus")]
    assert (url_hit.status.value, url_hit.detail) == ("hit", "listed: malware_download, online")
    assert rows[("domain", "evil-login.com", "virustotal")].status.value == "not_found"
    assert rows[("domain", "evil-login.com", "urlhaus")].status.value == "not_found"
    rdap_row = rows[("domain", "evil-login.com", "rdap")]
    assert rdap_row.status.value == "hit"
    assert rdap_row.raw["registered"] == registered.isoformat()


def test_reprocessing_does_not_duplicate_intel(
    make_settings, worker_context, session_factory, store
) -> None:
    report_id = stored(session_factory, store, phish("evil.example"))
    context = worker_context(make_settings())
    jobs.run_report(context, report_id)
    with session_factory() as session:
        first = session.scalar(select(func.count()).select_from(IntelResultRecord))
    jobs.run_report(context, report_id)  # e.g. an RQ retry after a crash
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(IntelResultRecord)) == first
    assert first


# --------------------------------------------------------------------------- RQ


def test_enqueue_options(fake_redis: FakeRedis) -> None:
    report_id = uuid.uuid4()
    queueing.rq_enqueuer(fake_redis)(report_id)
    job = Job.fetch(
        queueing.job_id(report_id), connection=fake_redis, serializer=queueing.SERIALIZER
    )
    assert job.func_name == "app.jobs.process_report"
    assert job.args == [str(report_id)]
    assert job.retries_left == 3
    assert job.retry_intervals == [10, 30, 90]  # exponential back-off
    assert job.timeout == 600
    assert job.failure_callback is jobs.on_report_failure
    raw = fake_redis.hget(job.key, "data")
    assert raw is not None
    # RQ zlib-compresses the payload; inside is JSON, not pickle.
    assert json.loads(zlib.decompress(raw))[2] == [str(report_id)]


def test_enqueue_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    from fakeredis import FakeServer

    server = FakeServer()
    server.connected = False
    with pytest.raises(queueing.QueueUnavailable):
        queueing.rq_enqueuer(FakeRedis(server=server))(uuid.uuid4())


def test_worker_processes_a_queued_report(
    make_settings,
    worker_context,
    session_factory,
    store,
    fake_redis: FakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "get_context", lambda: worker_context(make_settings()))
    report_id = stored(session_factory, store, phish("evil.example"))
    queueing.rq_enqueuer(fake_redis)(report_id)
    worker = SimpleWorker(
        [queueing.get_queue(fake_redis)], connection=fake_redis, serializer=queueing.SERIALIZER
    )
    worker.work(burst=True)
    with session_factory() as session:
        assert session.get(Report, report_id).status is ReportStatus.DONE


def test_failures_are_retried_then_mark_the_report_failed(
    make_settings,
    worker_context,
    session_factory,
    store,
    fake_redis: FakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[uuid.UUID] = []

    def crash(context: object, report_id: uuid.UUID) -> None:
        attempts.append(report_id)
        raise ConnectionError("database went away")

    monkeypatch.setattr(jobs, "get_context", lambda: worker_context(make_settings()))
    monkeypatch.setattr(jobs, "run_report", crash)
    report_id = stored(session_factory, store, phish("evil.example"))
    queue = queueing.get_queue(fake_redis)
    queueing.enqueue_report(queue, report_id)
    worker = SimpleWorker([queue], connection=fake_redis, serializer=queueing.SERIALIZER)

    worker.work(burst=True)
    job = Job.fetch(
        queueing.job_id(report_id), connection=fake_redis, serializer=queueing.SERIALIZER
    )
    assert job.get_status() == JobStatus.SCHEDULED  # back in 10 s
    assert job.id in ScheduledJobRegistry(queue=queue).get_job_ids()
    assert job.retries_left == 2
    with session_factory() as session:
        assert session.get(Report, report_id).status is ReportStatus.QUEUED  # not failed yet

    job.retries_left = 0  # pretend the retries are used up and run the last attempt
    job.save()
    queue.enqueue_job(job)
    worker.work(burst=True)
    assert len(attempts) == 2
    with session_factory() as session:
        report = session.get(Report, report_id)
        assert report.status is ReportStatus.FAILED
        assert report.error == "processing failed (ConnectionError); gave up after 3 retries"


def test_mark_failed_leaves_finished_reports_alone(
    make_settings, worker_context, session_factory, store
) -> None:
    context = worker_context(make_settings())
    report_id = stored(session_factory, store, phish("evil.example"))
    jobs.run_report(context, report_id)
    jobs.mark_failed(context, report_id, "late failure")
    jobs.mark_failed(context, uuid.uuid4(), "unknown report")
    with session_factory() as session:
        assert session.get(Report, report_id).status is ReportStatus.DONE


# --------------------------------------------------------------------------- requeue


def test_requeue_reports(session_factory, store) -> None:
    with session_factory() as session:
        failed = submit(session, store, b"Subject: a\r\n\r\nx", source=ReportSource.API)
        failed.status = ReportStatus.FAILED
        failed.error = "could not be queued"
        stuck = submit(session, store, b"Subject: b\r\n\r\nx", source=ReportSource.API)
        stuck.received_at = datetime.now(UTC) - timedelta(hours=2)
        fresh = submit(session, store, b"Subject: c\r\n\r\nx", source=ReportSource.API)
        child = Report(
            parent_id=fresh.id,
            source=ReportSource.API,
            status=ReportStatus.DONE,
            submission_sha256="0" * 64,
            submission_size=1,
        )
        session.add(child)
        session.commit()
        ids = {"failed": failed.id, "stuck": stuck.id, "fresh": fresh.id, "child": child.id}

    queued: list[uuid.UUID] = []
    with session_factory() as session:
        assert requeue_reports(session, queued.append) == []
        done = requeue_reports(
            session,
            queued.append,
            [ids["child"]],
            failed=True,
            stuck_before=datetime.now(UTC) - timedelta(minutes=15),
        )
    assert set(done) == set(queued) == {ids["failed"], ids["stuck"], ids["fresh"]}
    with session_factory() as session:
        report = session.get(Report, ids["failed"])
        assert (report.status, report.error) == (ReportStatus.QUEUED, None)


def test_cli_requeue(
    monkeypatch: pytest.MonkeyPatch, session_factory, store, fake_redis: FakeRedis
) -> None:
    import app.db.session
    import app.redis_client

    with session_factory() as session:
        report = submit(session, store, b"Subject: a\r\n\r\nx", source=ReportSource.API)
        report.status = ReportStatus.FAILED
        session.commit()
    monkeypatch.setattr(app.db.session, "get_sessionmaker", lambda: session_factory)
    monkeypatch.setattr(app.redis_client, "redis_client", lambda url: fake_redis)
    out = io.StringIO()
    assert cli.main(["requeue", "--failed"], out=out) == 0
    assert out.getvalue().splitlines() == ["queued 1 report(s)", str(report.id)]
    assert fake_redis.exists(f"rq:job:{queueing.job_id(report.id)}")
    assert cli.main(["requeue", "not-a-uuid"], out=out) == 2


def test_http_mock_blocks_the_network(http_mock: respx.Router) -> None:
    """The autouse respx router: an unplanned request fails instead of leaving the machine."""
    with pytest.raises(Exception, match="not mocked"):
        httpx.get("https://www.virustotal.com/api/v3/files/" + "0" * 64)
