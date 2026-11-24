"""The one code path every intake channel uses to accept a submission."""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Report, ReportSource
from app.pipeline import process, submit
from app.storage import BlobStore


def accept_submission(
    app: FastAPI,
    session: Session,
    raw: bytes,
    *,
    source: ReportSource,
    reporter_email: str | None = None,
) -> Report:
    """Store the message and create a report, then process it.

    M1 processes synchronously inside the request; M3 replaces the ``process`` call with
    putting the report ID on the queue, so the web process never parses email.
    """
    settings: Settings = app.state.settings
    store: BlobStore = app.state.store
    report = submit(session, store, raw, source=source, reporter_email=reporter_email)
    session.commit()
    return process(session, store, report.id, settings.policy)
