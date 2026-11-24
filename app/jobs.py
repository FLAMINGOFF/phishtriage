"""RQ jobs, executed by the worker (``python -m app.worker``).

``process_report`` runs the whole pipeline for one report: parse, extract indicators, look
them up, run the rules, score, store, reply. A crash or a timeout makes RQ retry the job
(see app.queueing: 3 retries, 10/30/90 s apart); ``process`` is idempotent, so a retry
starts from a clean slate. Only when the last attempt fails is the report marked failed.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from functools import lru_cache
from types import TracebackType
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.db.models import Report, ReportStatus, utcnow
from app.db.session import get_sessionmaker
from app.intel.service import IntelLookup, build_intel_service
from app.notify.reply import notify_reporter
from app.pipeline import process
from app.queueing import MAX_RETRIES
from app.redis_client import get_redis
from app.storage import BlobStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkerContext:
    settings: Settings
    sessionmaker: sessionmaker[Session]
    store: BlobStore
    intel: IntelLookup


@lru_cache(maxsize=1)
def get_context() -> WorkerContext:
    """Built once per worker process: settings, database, blob store, intel clients."""
    settings = get_settings()
    return WorkerContext(
        settings=settings,
        sessionmaker=get_sessionmaker(),
        store=BlobStore(settings.storage_dir),
        intel=build_intel_service(settings, get_redis()),
    )


def run_report(ctx: WorkerContext, report_id: uuid.UUID) -> ReportStatus:
    with ctx.sessionmaker() as session:
        report = process(
            session,
            ctx.store,
            report_id,
            ctx.settings.policy,
            intel=ctx.intel,
            rules_file=ctx.settings.rules_file,
        )
        if report.status is ReportStatus.DONE:
            try:
                notify_reporter(session, report, ctx.settings)
            except Exception:
                # The analysis is stored; a reply problem must not make RQ redo it.
                logger.exception("report %s: reply step failed", report.id)
                session.rollback()
        return report.status


def process_report(report_id: str) -> str:
    """RQ entry point. The argument is a string because jobs are serialised as JSON."""
    return run_report(get_context(), uuid.UUID(report_id)).value


def mark_failed(ctx: WorkerContext, report_id: uuid.UUID, reason: str) -> None:
    with ctx.sessionmaker() as session:
        report = session.get(Report, report_id)
        if report is None or report.status is ReportStatus.DONE:
            return
        report.status = ReportStatus.FAILED
        report.error = reason
        report.analyzed_at = utcnow()
        session.commit()


def on_report_failure(
    job: Any,
    connection: Any,
    exc_type: type[BaseException] | None,
    exc_value: BaseException | None,
    traceback: TracebackType | None,
) -> None:
    """RQ calls this after *every* failed attempt; only the last one fails the report."""
    if job.retries_left:
        logger.warning(
            "job %s failed (%s), %d retries left",
            job.id,
            exc_type.__name__ if exc_type else "unknown error",
            job.retries_left,
        )
        return
    name = exc_type.__name__ if exc_type else "unknown error"
    # Only the exception type is stored: messages can quote attacker-controlled input.
    mark_failed(
        get_context(),
        uuid.UUID(str(job.args[0])),
        f"processing failed ({name}); gave up after {MAX_RETRIES} retries",
    )


def purge_expired() -> dict[str, int]:
    """RQ entry point for the daily retention purge (queued by the poller)."""
    from app.retention import purge_expired as purge

    ctx = get_context()
    with ctx.sessionmaker() as session:
        result = purge(session, ctx.store, retention_days=ctx.settings.retention_days)
    return {
        "reports": result.reports,
        "files_deleted": result.files_deleted,
        "files_kept": result.files_kept,
    }
