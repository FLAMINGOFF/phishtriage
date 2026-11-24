"""The one code path every intake channel uses to accept a submission."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import datetime

from fastapi import FastAPI
from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.orm import Session

from app.db.models import Report, ReportSource, ReportStatus
from app.pipeline import submit
from app.queueing import Enqueue, QueueUnavailable
from app.storage import BlobStore

logger = logging.getLogger(__name__)


def accept_submission(
    app: FastAPI,
    session: Session,
    raw: bytes,
    *,
    source: ReportSource,
    reporter_email: str | None = None,
) -> Report:
    """Store the message, create a queued report and hand it to the worker.

    The web process never parses the email: it only stores the bytes and queues the ID.
    If the queue is down the report is kept but marked failed (it can be re-queued with
    ``python -m app.cli requeue``), and :class:`QueueUnavailable` is raised.
    """
    store: BlobStore = app.state.store
    enqueue: Enqueue = app.state.enqueue
    report = submit(session, store, raw, source=source, reporter_email=reporter_email)
    session.commit()
    try:
        enqueue(report.id)
    except QueueUnavailable:
        logger.exception("could not queue report %s", report.id)
        report.status = ReportStatus.FAILED
        report.error = "could not be queued (Redis unavailable); re-queue it later"
        session.commit()
        raise
    return report


def requeue_reports(
    session: Session,
    enqueue: Enqueue,
    report_ids: Iterable[uuid.UUID] = (),
    *,
    failed: bool = False,
    stuck_before: datetime | None = None,
) -> list[uuid.UUID]:
    """Queue reports again: the given IDs, all failed ones, and/or ones stuck since a time.

    A report split into several (one per attached original) is re-queued through its
    first report, which rebuilds the others. Returns the IDs that were queued.
    """
    conditions: list[ColumnElement[bool]] = []
    ids = list(report_ids)
    if ids:
        conditions.append(Report.id.in_(ids))
    if failed:
        conditions.append(Report.status == ReportStatus.FAILED)
    if stuck_before is not None:
        conditions.append(
            Report.status.in_([ReportStatus.QUEUED, ReportStatus.ANALYZING])
            & (Report.received_at < stuck_before)
        )
    if not conditions:
        return []
    roots: dict[uuid.UUID, Report] = {}
    for report in session.scalars(select(Report).where(or_(*conditions))):
        root = session.get(Report, report.parent_id) if report.parent_id else report
        if root is not None:
            roots[root.id] = root
    for root in roots.values():
        root.status = ReportStatus.QUEUED
        root.error = None
    session.commit()
    for report_id in roots:
        enqueue(report_id)
    return list(roots)
