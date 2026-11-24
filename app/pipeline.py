"""Report processing: from stored raw message to persisted email, attachments and IOCs.

``submit`` stores a submission and creates a queued report; it is cheap and used by every
intake channel. ``process`` does the actual work and is idempotent, so a retry after a
crash starts from a clean slate instead of duplicating rows.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Policy
from app.db.models import (
    Attachment,
    Email,
    Observable,
    ObservableType,
    Report,
    ReportSource,
    ReportStatus,
    utcnow,
)
from app.parsing.eml import (
    DEFAULT_LIMITS,
    Limits,
    MessageRejected,
    ParsedEmail,
    extract_originals,
)
from app.parsing.filetype import detect_type
from app.parsing.html import sanitize_html
from app.parsing.iocs import extract_observables
from app.storage import BlobStore

logger = logging.getLogger(__name__)


def submit(
    session: Session,
    store: BlobStore,
    raw: bytes,
    *,
    source: ReportSource,
    reporter_email: str | None = None,
    outer_message_id: str | None = None,
    received_at: datetime | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Report:
    """Store a submitted message and create a queued report (caller commits)."""
    if len(raw) > limits.max_bytes:
        raise MessageRejected(
            f"message is {len(raw):,} bytes, the limit is {limits.max_bytes:,} bytes"
        )
    blob = store.put(raw, "raw")
    report = Report(
        source=source,
        reporter_email=reporter_email.lower() if reporter_email else None,
        received_at=received_at or utcnow(),
        status=ReportStatus.QUEUED,
        submission_path=blob.path,
        submission_sha256=blob.sha256,
        submission_size=blob.size,
        outer_message_id=outer_message_id,
    )
    session.add(report)
    session.flush()
    return report


def _reset(session: Session, report: Report) -> None:
    """Remove results of an earlier attempt so that processing can be retried safely."""
    report.email = None
    report.attachments.clear()
    report.observables.clear()
    # Query instead of trusting report.children: the collection may be stale in this session.
    for child in session.scalars(select(Report).where(Report.parent_id == report.id)).all():
        session.delete(child)
    session.flush()
    session.expire(report, ["children"])
    report.error = None


def _child_of(report: Report) -> Report:
    return Report(
        id=uuid.uuid4(),
        parent_id=report.id,
        source=report.source,
        reporter_email=report.reporter_email,
        received_at=report.received_at,
        status=ReportStatus.ANALYZING,
        intake_mode=report.intake_mode,
        submission_path=report.submission_path,
        submission_sha256=report.submission_sha256,
        submission_size=report.submission_size,
        outer_message_id=report.outer_message_id,
    )


def _persist_email(
    session: Session, store: BlobStore, report: Report, parsed: ParsedEmail, policy: Policy
) -> None:
    blob = store.put(parsed.raw, "raw")
    report.email = Email(
        raw_path=blob.path,
        raw_sha256=parsed.sha256,
        size=parsed.size,
        message_id=parsed.message_id,
        subject=parsed.subject,
        from_addr=parsed.from_addr.address if parsed.from_addr else None,
        from_display=parsed.from_addr.display_name if parsed.from_addr else None,
        reply_to=", ".join(a.address for a in parsed.reply_to) or None,
        return_path=parsed.return_path,
        to_addrs=[a.address for a in parsed.to],
        sent_at=parsed.sent_at,
        headers=[list(h) for h in parsed.headers],
        auth_results=[a.model_dump(mode="json") for a in parsed.authentication_results],
        received_hops=[h.model_dump(mode="json") for h in parsed.received],
        body_text=parsed.body_text,
        body_html_clean=sanitize_html(parsed.body_html) if parsed.body_html else None,
        forwarded_inline=parsed.forwarded_inline,
        defects=parsed.defects,
    )
    for attachment in parsed.attachments:
        stored = store.put(attachment.content, "attachments")
        report.attachments.append(
            Attachment(
                filename=attachment.filename,
                declared_type=attachment.declared_type[:255],
                detected_type=detect_type(attachment.content),
                size=attachment.size,
                sha256=attachment.sha256,
                storage_path=stored.path,
            )
        )
    for observable in extract_observables(parsed, own_domains=policy.org_domains):
        report.observables.append(
            Observable(
                type=ObservableType(observable.type),
                value=observable.value,
                defanged=observable.defanged[:4096],
            )
        )


def process(session: Session, store: BlobStore, report_id: uuid.UUID, policy: Policy) -> Report:
    """Parse a submitted report and persist the results. Returns the (first) report."""
    report = session.get(Report, report_id)
    if report is None:
        raise LookupError(f"report {report_id} not found")
    report.status = ReportStatus.ANALYZING
    session.commit()

    try:
        if report.submission_path is None:
            raise MessageRejected("the submitted message is no longer stored")
        raw = store.read(report.submission_path)
        intake = extract_originals(raw, is_report_wrapper=report.source is ReportSource.IMAP)
    except MessageRejected as exc:
        logger.info("report %s rejected: %s", report.id, exc.reason)
        _reset(session, report)
        report.status = ReportStatus.FAILED
        report.error = f"rejected: {exc.reason}"
        report.analyzed_at = utcnow()
        session.commit()
        return report

    _reset(session, report)
    report.intake_mode = intake.mode
    targets = [report]
    for _ in intake.originals[1:]:
        child = _child_of(report)
        report.children.append(child)
        targets.append(child)
    for target, original in zip(targets, intake.originals, strict=True):
        _persist_email(session, store, target, original, policy)
        target.status = ReportStatus.DONE
        target.analyzed_at = utcnow()
    session.commit()
    logger.info("report %s processed (%s, %d original(s))", report.id, intake.mode, len(targets))
    return report
