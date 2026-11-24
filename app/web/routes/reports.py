"""Report pages. M4 turns this into the full analyst detail view.

While a report waits in the queue or is being analysed, the page polls a small status
fragment (htmx, every 2 s); when the worker is done, the fragment tells htmx to reload.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db.models import IntelStatus, Report, ReportStatus
from app.intel.models import PROVIDER_LABELS
from app.scoring.engine import RULES_FILE, VERDICT_LABELS, cached_rules
from app.web.deps import get_session
from app.web.templating import templates

router = APIRouter(tags=["reports"])

PENDING = (ReportStatus.QUEUED, ReportStatus.ANALYZING)


def _get_report(session: Session, report_id: uuid.UUID) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "report not found")
    return report


def skipped_lookups(report: Report) -> list[tuple[str, str, int]]:
    """(provider label, reason, count) for lookups that were not made, most common first."""
    counts = Counter(
        (PROVIDER_LABELS[r.provider.value], r.detail or "")
        for o in report.observables
        for r in o.intel_results
        if r.status is IntelStatus.SKIPPED
    )
    return [(label, reason, n) for (label, reason), n in counts.most_common()]


@router.get("/", include_in_schema=False)
def index() -> Response:
    return RedirectResponse("/upload", status_code=303)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_detail(
    request: Request, report_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]
) -> Response:
    report = _get_report(session, report_id)
    rules = cached_rules(request.app.state.settings.rules_file or RULES_FILE)
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "report": report,
            "verdict_labels": VERDICT_LABELS,
            "rule_descriptions": {rule_id: r.description for rule_id, r in rules.rules.items()},
            "pending": report.status in PENDING,
            "provider_labels": PROVIDER_LABELS,
            "skipped_lookups": skipped_lookups(report),
        },
    )


@router.get("/reports/{report_id}/status", response_class=HTMLResponse)
def report_status(
    request: Request, report_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]
) -> Response:
    report = _get_report(session, report_id)
    if report.status in PENDING:
        return templates.TemplateResponse(request, "_status.html", {"report": report})
    # Finished: ask htmx to reload the whole page, which now shows the results.
    return Response(status_code=200, headers={"HX-Refresh": "true"})
