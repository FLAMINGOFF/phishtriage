"""Data retention: raw messages and attachments are deleted after ``RETENTION_DAYS`` (90).

What is deleted, for every report received before the cut-off:

* the stored raw submission (the email the employee sent us) and the attachment files;
* the email bodies kept in the database (``body_text``, ``body_html_clean``): they are the
  content of somebody's mailbox, which is what the retention period is about.

What stays: the report, its verdicts, matched rules with their evidence, the headers,
indicators and intel answers. Statistics, IOC exports, the audit trail and the evaluation
of the rules keep working on old reports.

Files are content-addressed, so one file can belong to several reports (the same
attachment reported in March and again in June). A file is only deleted when no report
that is still inside the retention period refers to it.

Files are deleted *before* the database rows are updated: if the job dies in between, the
rows still point at the (now missing) files and the next run finishes the job. The other
order could leave files that nothing points to, which nothing would ever delete.

The purge runs once a day as an RQ job (``app.jobs.purge_expired``). The poller, the one
process with a timer loop, queues it; a Redis key with a one-day expiry makes sure that
restarts or several pollers still queue it at most once a day. ``python -m app.cli purge``
runs it by hand (``--dry-run`` only counts).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.db.models import Attachment, Email, Report, utcnow
from app.storage import BlobStore

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
SCHEDULE_KEY = "phishtriage:retention:queued"
SCHEDULE_INTERVAL = timedelta(days=1)


@dataclass
class PurgeResult:
    reports: int = 0
    files_deleted: int = 0
    files_kept: int = 0  # still used by a report inside the retention period
    cutoff: datetime | None = None
    report_ids: list[str] = field(default_factory=list)


def _paths_of(report: Report) -> set[str]:
    paths = {report.submission_path} if report.submission_path else set()
    if report.email is not None and report.email.raw_path:
        paths.add(report.email.raw_path)
    paths.update(a.storage_path for a in report.attachments if a.storage_path)
    return paths


def _still_used(session: Session, paths: set[str], expiring: Iterable[Report]) -> set[str]:
    """The subset of ``paths`` that a report outside ``expiring`` still refers to."""
    if not paths:
        return set()
    skip = [r.id for r in expiring]
    used: set[str] = set()
    for column, owner in (
        (Report.submission_path, Report.id),
        (Email.raw_path, Email.report_id),
        (Attachment.storage_path, Attachment.report_id),
    ):
        rows = session.scalars(
            select(column).where(column.in_(paths), owner.not_in(skip)).distinct()
        )
        used.update(path for path in rows if path)
    return used


def purge_expired(
    session: Session,
    store: BlobStore,
    *,
    retention_days: int,
    now: datetime | None = None,
    dry_run: bool = False,
) -> PurgeResult:
    """Delete the stored content of every report received more than ``retention_days`` ago."""
    now = now or utcnow()
    result = PurgeResult(cutoff=now - timedelta(days=retention_days))
    deleted: set[str] = set()
    kept: set[str] = set()
    while True:
        query = (
            select(Report)
            .where(Report.received_at < result.cutoff, Report.purged_at.is_(None))
            .order_by(Report.received_at, Report.id)
            .limit(BATCH_SIZE)
            .options(selectinload(Report.email), selectinload(Report.attachments))
        )
        if dry_run:  # nothing changes, so page through instead
            query = query.offset(result.reports)
        batch = list(session.scalars(query))
        if not batch:
            break
        paths: set[str] = set().union(*(_paths_of(r) for r in batch))
        shared = _still_used(session, paths, batch)
        kept |= shared
        result.reports += len(batch)
        result.report_ids.extend(str(r.id) for r in batch)
        if dry_run:
            deleted |= paths - shared
            continue
        for path in sorted(paths - shared):
            try:
                if store.delete(path):
                    deleted.add(path)
            except ValueError:
                logger.warning("not a blob path, left alone: %r", path)
        for report in batch:
            report.submission_path = None
            report.purged_at = now
            if report.email is not None:
                report.email.raw_path = None
                report.email.body_text = ""
                report.email.body_html_clean = None
            for attachment in report.attachments:
                attachment.storage_path = None
        session.commit()
    result.files_deleted = len(deleted)
    # A file kept for a newer report in one batch can be deleted by a later batch.
    result.files_kept = len(kept - deleted)
    if result.reports and not dry_run:
        audit.record(
            session,
            audit.RETENTION_PURGE,
            reports=result.reports,
            files_deleted=result.files_deleted,
            files_kept=result.files_kept,
            retention_days=retention_days,
        )
        session.commit()
        logger.info(
            "retention: purged %d report(s), deleted %d file(s), kept %d still in use",
            result.reports,
            result.files_deleted,
            result.files_kept,
        )
    return result


def queue_daily_purge(redis: Redis, queue_job: Callable[[], None]) -> bool:
    """Queue the purge job unless that already happened in the last day. True if queued."""
    if not redis.set(SCHEDULE_KEY, utcnow().isoformat(), nx=True, ex=SCHEDULE_INTERVAL):
        return False
    try:
        queue_job()
    except Exception:
        redis.delete(SCHEDULE_KEY)  # try again in the next round
        raise
    logger.info("queued the daily retention purge")
    return True
