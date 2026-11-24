"""Analyst console: the report queue, the detail page and the actions on one report.

Every route here needs a logged-in analyst (the router-wide ``require_user``), and every
POST needs the CSRF token. While a report waits in the queue or is being analysed, its
page polls a small status fragment (htmx, every 2 s) and reloads itself when it is done.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from app import audit
from app.db.models import (
    Attachment,
    AuditLog,
    Email,
    IntelStatus,
    Report,
    ReportStatus,
    User,
    Verdict,
    utcnow,
)
from app.export.infected_zip import PASSWORD, infected_zip, safe_filename
from app.ingest.submission import requeue_reports
from app.intel.models import PROVIDER_LABELS
from app.queueing import QueueUnavailable
from app.scoring.engine import RULES_FILE, VERDICT_LABELS, cached_rules
from app.storage import BlobStore
from app.web.deps import get_session, get_store, require_csrf, require_user
from app.web.templating import templates

router = APIRouter(tags=["reports"], dependencies=[Depends(require_user)])

PENDING = (ReportStatus.QUEUED, ReportStatus.ANALYZING)
PAGE_SIZE = 50
MAX_NOTE_LENGTH = 2000
SORTS = {
    "newest": (Report.received_at.desc(),),
    "oldest": (Report.received_at.asc(),),
    "score": (Report.score.desc().nulls_last(), Report.received_at.desc()),
}
# Report-level activity shown on the detail page, newest first.
ACTIVITY_LIMIT = 100

CurrentUser = Annotated[User, Depends(require_user)]
DbSession = Annotated[Session, Depends(get_session)]


def final_verdict_column() -> ColumnElement[Any]:
    """The analyst's verdict where there is one, else the automatic one."""
    return func.coalesce(Report.analyst_verdict, Report.verdict)


def _get_report(session: Session, report_id: uuid.UUID) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "report not found")
    return report


def _choice(enum: type[Verdict] | type[ReportStatus], value: str) -> Any:
    """A filter value from the query string; unknown values mean "no filter"."""
    try:
        return enum(value)
    except ValueError:
        return None


def skipped_lookups(report: Report) -> list[tuple[str, str, int]]:
    """(provider label, reason, count) for lookups that were not made, most common first."""
    counts = Counter(
        (PROVIDER_LABELS[r.provider.value], r.detail or "")
        for o in report.observables
        for r in o.intel_results
        if r.status is IntelStatus.SKIPPED
    )
    return [(label, reason, n) for (label, reason), n in counts.most_common()]


def can_requeue(report: Report) -> bool:
    """Re-analysis from the console: finished, stand-alone reports only.

    Re-analysing a split submission rebuilds its other reports under new IDs, which
    would drop their analyst verdicts; ``python -m app.cli requeue`` covers that case.
    """
    return (
        report.status not in PENDING
        and report.parent_id is None
        and not report.children
        and report.purged_at is None
    )


# --------------------------------------------------------------------------- pages


@router.get("/", include_in_schema=False)
def index() -> Response:
    return RedirectResponse("/reports", status_code=303)


@router.get("/reports", response_class=HTMLResponse)
def report_queue(
    request: Request,
    session: DbSession,
    verdict: str = "",
    status: str = "",
    reviewed: str = "",
    sort: str = "newest",
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
) -> Response:
    conditions: list[ColumnElement[bool]] = []
    verdict_filter = _choice(Verdict, verdict)
    if verdict == "none":
        conditions.append(final_verdict_column().is_(None))
    elif verdict_filter is not None:
        conditions.append(final_verdict_column() == verdict_filter)
    status_filter = _choice(ReportStatus, status)
    if status_filter is not None:
        conditions.append(Report.status == status_filter)
    if reviewed == "yes":
        conditions.append(Report.analyst_verdict.is_not(None))
    elif reviewed == "no":
        conditions.append(Report.analyst_verdict.is_(None))
    order = SORTS.get(sort, SORTS["newest"])

    total = session.scalar(select(func.count()).select_from(Report).where(*conditions)) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(page, pages)
    rows = session.execute(
        select(
            Report.id,
            Report.received_at,
            Report.source,
            Report.status,
            Report.score,
            Report.verdict,
            Report.analyst_verdict,
            Report.reporter_email,
            Report.parent_id,
            Email.subject,
            Email.from_addr,
        )
        .outerjoin(Email, Email.report_id == Report.id)
        .where(*conditions)
        .order_by(*order, Report.id)
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    filters = {
        "verdict": verdict if verdict_filter is not None or verdict == "none" else "",
        "status": status_filter.value if status_filter is not None else "",
        "reviewed": reviewed if reviewed in ("yes", "no") else "",
        "sort": sort if sort in SORTS else "newest",
    }
    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "rows": rows,
            "total": total,
            "page": page,
            "pages": pages,
            "filters": filters,
            "query": {
                k: v for k, v in filters.items() if v and not (k == "sort" and v == "newest")
            },
            "verdicts": list(Verdict),
            "statuses": list(ReportStatus),
            "verdict_labels": VERDICT_LABELS,
        },
    )


def _activity(session: Session, report: Report) -> list[AuditLog]:
    return list(
        session.scalars(
            select(AuditLog)
            .where(AuditLog.report_id == report.id)
            .order_by(AuditLog.created_at.desc())
            .limit(ACTIVITY_LIMIT)
        )
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_detail(request: Request, report_id: uuid.UUID, session: DbSession) -> Response:
    report = _get_report(session, report_id)
    settings = request.app.state.settings
    rules = cached_rules(settings.rules_file or RULES_FILE)
    trusted = set(settings.policy.trusted_authserv_ids)
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "report": report,
            "verdicts": list(Verdict),
            "verdict_labels": VERDICT_LABELS,
            "rule_descriptions": {rule_id: r.description for rule_id, r in rules.rules.items()},
            "pending": report.status in PENDING,
            "provider_labels": PROVIDER_LABELS,
            "skipped_lookups": skipped_lookups(report),
            "activity": _activity(session, report),
            "trusted_authserv_ids": trusted,
            "can_requeue": can_requeue(report),
            "retention_days": request.app.state.settings.retention_days,
            "zip_password": PASSWORD.decode(),
            "max_note_length": MAX_NOTE_LENGTH,
        },
    )


@router.get("/reports/{report_id}/status", response_class=HTMLResponse)
def report_status(request: Request, report_id: uuid.UUID, session: DbSession) -> Response:
    report = _get_report(session, report_id)
    if report.status in PENDING:
        return templates.TemplateResponse(request, "_status.html", {"report": report})
    # Finished: ask htmx to reload the whole page, which now shows the results.
    return Response(status_code=200, headers={"HX-Refresh": "true"})


# The sanitised HTML body is shown in <iframe sandbox>, from its own URL, under a CSP that
# lets it load nothing at all. The sanitiser already removed scripts, styles, links and
# images; the sandbox and the CSP are the second and third line of defence.
BODY_CSP = (
    "default-src 'none'; sandbox; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)


@router.get("/reports/{report_id}/body", response_class=HTMLResponse)
def report_body(report_id: uuid.UUID, session: DbSession) -> Response:
    report = _get_report(session, report_id)
    if report.email is None or not report.email.body_html_clean:
        raise HTTPException(404, "this email has no HTML body")
    document = (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer"></head>'
        f"<body>{report.email.body_html_clean}</body></html>"
    )
    return HTMLResponse(
        document,
        headers={
            "content-security-policy": BODY_CSP,
            "x-frame-options": "SAMEORIGIN",
            "cross-origin-resource-policy": "same-origin",
        },
    )


# --------------------------------------------------------------------------- actions


def _back(report_id: uuid.UUID, anchor: str = "") -> RedirectResponse:
    return RedirectResponse(f"/reports/{report_id}{anchor}", status_code=303)


@router.post("/reports/{report_id}/verdict", dependencies=[Depends(require_csrf)])
def reclassify(
    report_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    verdict: Annotated[str, Form(max_length=32)] = "",
) -> Response:
    report = _get_report(session, report_id)
    new = _choice(Verdict, verdict) if verdict else None
    if verdict and new is None:
        raise HTTPException(422, "unknown verdict")
    if report.status is not ReportStatus.DONE:
        raise HTTPException(409, "only analysed reports can be re-classified")
    old = report.analyst_verdict
    if new != old:
        # The automatic score and verdict stay as they were: M6 compares them with the
        # analysts' decisions to tune the rule weights.
        report.analyst_verdict = new
        report.closed_at = utcnow() if new is not None else None
        audit.record(
            session,
            audit.REPORT_RECLASSIFY,
            user=user,
            report_id=report.id,
            previous=old.value if old else None,
            verdict=new.value if new else "automatic",
            automatic=report.verdict.value if report.verdict else None,
            score=report.score,
        )
        session.commit()
    return _back(report.id, "#review")


@router.post("/reports/{report_id}/notes", dependencies=[Depends(require_csrf)])
def add_note(
    report_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    text: Annotated[str, Form(max_length=MAX_NOTE_LENGTH)],
) -> Response:
    report = _get_report(session, report_id)
    note = text.strip()
    if not note:
        raise HTTPException(422, "the note is empty")
    audit.record(session, audit.REPORT_NOTE, user=user, report_id=report.id, text=note)
    session.commit()
    return _back(report.id, "#activity")


@router.post("/reports/{report_id}/requeue", dependencies=[Depends(require_csrf)])
def requeue(
    request: Request, report_id: uuid.UUID, session: DbSession, user: CurrentUser
) -> Response:
    report = _get_report(session, report_id)
    if not can_requeue(report):
        raise HTTPException(409, "this report cannot be re-analysed from the console")
    audit.record(session, audit.REPORT_REQUEUE, user=user, report_id=report.id)
    try:
        # requeue_reports commits (with the audit entry) before it enqueues.
        requeue_reports(session, request.app.state.enqueue, [report.id])
    except QueueUnavailable as exc:
        raise HTTPException(503, "the queue is unavailable; try again later") from exc
    return _back(report.id)


@router.get("/reports/{report_id}/attachments/{attachment_id}")
def download_attachment(
    report_id: uuid.UUID,
    attachment_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    store: Annotated[BlobStore, Depends(get_store)],
) -> Response:
    """The attachment inside a ZIP encrypted with the password "infected"; never raw."""
    attachment = session.get(Attachment, attachment_id)
    if attachment is None or attachment.report_id != report_id:
        raise HTTPException(404, "attachment not found")
    if attachment.storage_path is None:
        raise HTTPException(410, "the file is no longer stored (retention period)")
    try:
        content = store.read(attachment.storage_path)
    except FileNotFoundError as exc:
        raise HTTPException(410, "the file is no longer stored (retention period)") from exc
    archive = infected_zip(attachment.filename, content)
    audit.record(
        session,
        audit.ATTACHMENT_DOWNLOAD,
        user=user,
        report_id=report_id,
        attachment_id=str(attachment.id),
        sha256=attachment.sha256,
        filename=safe_filename(attachment.filename),
    )
    session.commit()
    # The download name is ours, not the attacker's: no header injection, no tricks.
    name = f"attachment-{attachment.sha256[:16]}.zip"
    return Response(
        archive,
        media_type="application/zip",
        headers={"content-disposition": f'attachment; filename="{name}"'},
    )
