"""Reply to the person who reported the email.

M3 only reserves the step in the pipeline; M5 implements the reply (SMTP, the English
templates and the anti-abuse rules: org_domains only, outer DMARC pass, per-reporter
hourly limit).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Report

logger = logging.getLogger(__name__)


def notify_reporter(session: Session, report: Report, settings: Settings) -> bool:
    """Send the verdict to the reporter if the rules allow it. Returns whether one was sent."""
    logger.debug("reply step for report %s: not implemented yet (M5)", report.id)
    return False
