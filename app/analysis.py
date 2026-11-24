"""One email in, one explained verdict out: inspect, analyze, score."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.runner import TIMEOUT_SECONDS, run_analyzers
from app.config import Policy
from app.intel.models import EMPTY_SNAPSHOT, IntelSnapshot
from app.parsing.attachments import AttachmentFacts, inspect_attachment
from app.parsing.eml import Attachment, ParsedEmail
from app.scoring.engine import RULES_FILE, ScoreResult, cached_rules, score

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Analysis:
    attachments: tuple[AttachmentFacts, ...]
    result: ScoreResult
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def error_summary(self) -> str | None:
        if not self.errors:
            return None
        return "partial analysis: " + "; ".join(f"{k} {v}" for k, v in sorted(self.errors.items()))


def _minimal_facts(attachment: Attachment) -> AttachmentFacts:
    return AttachmentFacts(
        filename=attachment.filename,
        declared_type=attachment.declared_type,
        detected_type=None,
        size=attachment.size,
        sha256=attachment.sha256,
    )


def inspect_attachments(
    attachments: list[Attachment], timeout: float = TIMEOUT_SECONDS
) -> tuple[tuple[AttachmentFacts, ...], str | None]:
    """Inspect every attachment within ``timeout``; on overrun, keep what is known."""
    if not attachments:
        return (), None
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="inspect")
    try:
        future = executor.submit(lambda: tuple(inspect_attachment(a) for a in attachments))
        return future.result(timeout=timeout), None
    except TimeoutError:
        logger.warning("attachment inspection timed out")
        return tuple(_minimal_facts(a) for a in attachments), f"timed out after {timeout:g} s"
    except Exception as exc:
        logger.exception("attachment inspection failed")
        return tuple(_minimal_facts(a) for a in attachments), f"failed: {type(exc).__name__}"
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def analyze_email(
    email: ParsedEmail,
    policy: Policy,
    *,
    intel: IntelSnapshot = EMPTY_SNAPSHOT,
    now: datetime | None = None,
    rules_file: Path | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> Analysis:
    facts, inspection_error = inspect_attachments(email.attachments, timeout)
    ctx = AnalysisContext(email=email, policy=policy, attachments=facts, intel=intel, now=now)
    run = run_analyzers(ctx, timeout=timeout)
    errors = dict(run.errors)
    if inspection_error:
        errors["inspection"] = inspection_error
    result = score(run.hits, cached_rules(rules_file or RULES_FILE))
    return Analysis(attachments=facts, result=result, errors=errors)
