"""The audit log: one row per security-relevant action (see AuditLog)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditLog, User

# Actions, so that the log and its filter use one vocabulary.
LOGIN_SUCCESS = "login.success"
LOGIN_FAILURE = "login.failure"
LOGIN_LOCKED = "login.locked"
LOGOUT = "logout"
REPORT_UPLOAD = "report.upload"
REPORT_RECLASSIFY = "report.reclassify"
REPORT_NOTE = "report.note"
REPORT_REQUEUE = "report.requeue"
ATTACHMENT_DOWNLOAD = "attachment.download"
EXPORT_CSV = "export.csv"
EXPORT_STIX = "export.stix"
RETENTION_PURGE = "retention.purge"

ACTIONS = (
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGIN_LOCKED,
    LOGOUT,
    REPORT_UPLOAD,
    REPORT_RECLASSIFY,
    REPORT_NOTE,
    REPORT_REQUEUE,
    ATTACHMENT_DOWNLOAD,
    EXPORT_CSV,
    EXPORT_STIX,
    RETENTION_PURGE,
)


def record(
    session: Session,
    action: str,
    *,
    user: User | None = None,
    report_id: uuid.UUID | None = None,
    **details: Any,
) -> AuditLog:
    """Add an entry to the session; the caller commits it with the change it describes."""
    entry = AuditLog(
        user_id=user.id if user else None,
        action=action,
        report_id=report_id,
        details={k: v for k, v in details.items() if v is not None},
    )
    session.add(entry)
    return entry
