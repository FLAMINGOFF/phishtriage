"""Submission and processing: reports, child reports, rejection and safe retries."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Policy
from app.db.models import (
    Attachment,
    Email,
    Finding,
    Observable,
    ObservableType,
    Report,
    ReportSource,
    ReportStatus,
    Verdict,
)
from app.parsing.eml import Limits, MessageRejected
from app.pipeline import process, submit
from app.storage import BlobStore

Loader = Callable[[str], bytes]


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_submit_stores_blob_and_queues(
    session_factory: sessionmaker[Session], store: BlobStore, fixture_bytes: Loader
) -> None:
    raw = fixture_bytes("01")
    with session_factory() as session:
        report = submit(session, store, raw, source=ReportSource.API, reporter_email="Bob@X.edu")
        session.commit()
        assert report.status is ReportStatus.QUEUED
        assert report.reporter_email == "bob@x.edu"
        assert report.submission_path is not None
        assert store.read(report.submission_path) == raw
        assert report.submission_size == len(raw)


def test_submit_refuses_oversize(session_factory: sessionmaker[Session], store: BlobStore) -> None:
    with session_factory() as session, pytest.raises(MessageRejected):
        submit(session, store, b"x" * 20, source=ReportSource.API, limits=Limits(max_bytes=10))
    assert not store.root.exists()


def test_process_direct_upload(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    with session_factory() as session:
        report = submit(session, store, fixture_bytes("09"), source=ReportSource.UPLOAD)
        session.commit()
        process(session, store, report.id, example_policy)

    with session_factory() as session:
        report = session.get(Report, report.id)
        assert report is not None
        assert report.status is ReportStatus.DONE
        assert report.intake_mode == "direct"
        assert report.analyzed_at is not None
        assert report.email is not None
        assert report.email.subject == "Scanned documents"
        by_name = {a.filename: a for a in report.attachments}
        assert by_name["statement.pdf"].detected_type == "application/x-dosexec"
        assert by_name["statement.pdf"].declared_type == "application/pdf"
        stored = by_name["statement.pdf"].storage_path
        assert stored is not None
        assert store.read(stored).startswith(b"MZ")
        assert any(o.type is ObservableType.SHA256 for o in report.observables)
        assert by_name["Report.docm"].has_macros is True
        assert by_name["documents.zip"].is_encrypted is True
        # M2: the verdict and its explanation are stored with the report.
        assert report.verdict is Verdict.MALICIOUS
        assert report.final_verdict is Verdict.MALICIOUS
        assert report.score == sum(f.score for f in report.findings)
        rules = [f.rule_id for f in report.findings]
        assert rules[0] == "ATT_EXECUTABLE"  # highest points first
        assert {"ATT_EXT_MISMATCH", "ATT_MACRO", "ATT_ENCRYPTED_ARCHIVE"} <= set(rules)
        executable = report.findings[0]
        assert executable.analyzer == "attachments"
        assert {"field", "value", "match"} <= set(executable.evidence[0])
        assert report.error is None


def test_process_wrapper_with_two_originals(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    with session_factory() as session:
        report = submit(
            session,
            store,
            fixture_bytes("08"),
            source=ReportSource.IMAP,
            reporter_email="alice@example.edu",
            outer_message_id="<r8@example.edu>",
        )
        session.commit()
        process(session, store, report.id, example_policy)

    with session_factory() as session:
        reports = session.scalars(select(Report).order_by(Report.parent_id.is_not(None))).all()
        assert len(reports) == 2
        parent, child = reports
        assert child.parent_id == parent.id
        assert {r.status for r in reports} == {ReportStatus.DONE}
        assert {r.intake_mode for r in reports} == {"attachment"}
        assert child.reporter_email == "alice@example.edu"
        assert child.outer_message_id == "<r8@example.edu>"
        assert parent.email is not None
        assert child.email is not None
        assert parent.email.subject != child.email.subject
        assert parent.children == [child]


def test_process_is_idempotent(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    with session_factory() as session:
        report = submit(session, store, fixture_bytes("08"), source=ReportSource.IMAP)
        session.commit()
        process(session, store, report.id, example_policy)
        models = (Report, Email, Attachment, Observable, Finding)
        counts = [_count(session, m) for m in models]
        assert counts[-1] > 0
        process(session, store, report.id, example_policy)
        assert [_count(session, m) for m in models] == counts


def test_children_get_their_own_verdict(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    with session_factory() as session:
        report = submit(session, store, fixture_bytes("08"), source=ReportSource.IMAP)
        session.commit()
        process(session, store, report.id, example_policy)
        assert report.verdict is Verdict.NO_ISSUES
        (child,) = report.children
        assert child.verdict is Verdict.SUSPICIOUS
        assert "ATT_HTML_FILE" in {f.rule_id for f in child.findings}


def test_tuned_rules_file_is_used(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
    tmp_path,
) -> None:
    import yaml

    from app.scoring.engine import RULES_FILE

    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    data["rules"]["URL_IP_HOST"]["score"] = 60
    tuned = tmp_path / "rules.yaml"
    tuned.write_text(yaml.safe_dump(data), encoding="utf-8")
    with session_factory() as session:
        report = submit(session, store, fixture_bytes("03"), source=ReportSource.UPLOAD)
        session.commit()
        process(session, store, report.id, example_policy, rules_file=tuned)
        assert report.score == 85
        assert report.verdict is Verdict.MALICIOUS


def test_process_rejection_marks_failed(
    session_factory: sessionmaker[Session], store: BlobStore, example_policy: Policy
) -> None:
    with session_factory() as session:
        report = submit(session, store, b"not an email at all", source=ReportSource.API)
        session.commit()
        process(session, store, report.id, example_policy)
        assert report.status is ReportStatus.FAILED
        assert report.error is not None
        assert report.error.startswith("rejected: ")
        assert report.email is None


def test_process_missing_blob_or_report(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    import uuid

    with session_factory() as session:
        with pytest.raises(LookupError):
            process(session, store, uuid.uuid4(), example_policy)
        report = submit(session, store, fixture_bytes("01"), source=ReportSource.API)
        report.submission_path = None
        session.commit()
        process(session, store, report.id, example_policy)
        assert report.status is ReportStatus.FAILED
        assert report.error == "rejected: the submitted message is no longer stored"


def test_final_verdict_prefers_analyst() -> None:
    report = Report(verdict=Verdict.SUSPICIOUS)
    assert report.final_verdict is Verdict.SUSPICIOUS
    report.analyst_verdict = Verdict.NO_ISSUES
    assert report.final_verdict is Verdict.NO_ISSUES


def test_deleting_a_report_cascades(
    session_factory: sessionmaker[Session],
    store: BlobStore,
    fixture_bytes: Loader,
    example_policy: Policy,
) -> None:
    with session_factory() as session:
        report = submit(session, store, fixture_bytes("08"), source=ReportSource.IMAP)
        session.commit()
        process(session, store, report.id, example_policy)
        session.delete(report)
        session.commit()
        models = (Report, Email, Attachment, Observable, Finding)
        assert [_count(session, m) for m in models] == [0] * 5
