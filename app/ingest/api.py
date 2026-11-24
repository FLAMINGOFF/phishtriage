"""REST API for automation and tests.

``POST /api/reports`` takes a raw message (``Content-Type: message/rfc822``), queues it
and answers ``202 Accepted`` with the new report (status ``queued``); poll
``GET /api/reports/{id}`` until the status is ``done`` or ``failed``.
Authentication is a bearer token (``API_TOKEN``); without one configured the API is off.
Cookies are never accepted here, so cross-site requests cannot use an analyst's session.
"""

from __future__ import annotations

import hmac
import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Report, ReportSource
from app.ingest.submission import accept_submission
from app.parsing.eml import MAX_MESSAGE_BYTES
from app.queueing import QueueUnavailable
from app.web.deps import get_app_settings, get_session, read_body_limited

router = APIRouter(prefix="/api", tags=["api"])

ACCEPTED_TYPES = {"message/rfc822", "application/octet-stream"}
_EMAIL = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,255}$")


def require_api_token(
    settings: Annotated[Settings, Depends(get_app_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    if settings.api_token is None:
        raise HTTPException(403, "API disabled: set API_TOKEN to enable it")
    scheme, _, token = (authorization or "").partition(" ")
    expected = settings.api_token.get_secret_value().encode()
    # compare_digest: the comparison time does not reveal how much of the token matched.
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip().encode(), expected):
        raise HTTPException(
            401, "missing or invalid bearer token", headers={"WWW-Authenticate": "Bearer"}
        )


class IntelOut(BaseModel):
    provider: str
    status: str
    malicious_count: int | None
    detail: str | None
    fetched_at: datetime | None


class ObservableOut(BaseModel):
    type: str
    value: str
    defanged: str
    intel: list[IntelOut]


class FindingOut(BaseModel):
    rule_id: str
    analyzer: str
    score: int
    evidence: list[dict[str, str]]


class ReportOut(BaseModel):
    id: uuid.UUID
    parent_id: uuid.UUID | None
    status: str
    source: str
    intake_mode: str | None
    received_at: datetime
    analyzed_at: datetime | None
    score: int | None
    verdict: str | None
    analyst_verdict: str | None
    error: str | None
    subject: str | None
    from_addr: str | None
    forwarded_inline: bool | None
    findings: list[FindingOut]
    observables: list[ObservableOut]
    related: list[uuid.UUID]

    @classmethod
    def of(cls, report: Report) -> ReportOut:
        email = report.email
        return cls(
            id=report.id,
            parent_id=report.parent_id,
            status=report.status.value,
            source=report.source.value,
            intake_mode=report.intake_mode,
            received_at=report.received_at,
            analyzed_at=report.analyzed_at,
            score=report.score,
            verdict=report.verdict.value if report.verdict else None,
            analyst_verdict=report.analyst_verdict.value if report.analyst_verdict else None,
            error=report.error,
            subject=email.subject if email else None,
            from_addr=email.from_addr if email else None,
            forwarded_inline=email.forwarded_inline if email else None,
            findings=[
                FindingOut(
                    rule_id=f.rule_id, analyzer=f.analyzer, score=f.score, evidence=f.evidence
                )
                for f in report.findings
            ],
            observables=[
                ObservableOut(
                    type=o.type.value,
                    value=o.value,
                    defanged=o.defanged,
                    intel=[
                        IntelOut(
                            provider=r.provider.value,
                            status=r.status.value,
                            malicious_count=r.malicious_count,
                            detail=r.detail,
                            fetched_at=r.fetched_at,
                        )
                        for r in o.intel_results
                    ],
                )
                for o in report.observables
            ],
            related=[child.id for child in report.children],
        )


@router.post("/reports", status_code=202, dependencies=[Depends(require_api_token)])
async def create_report(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    reporter_email: Annotated[str | None, Query(max_length=320)] = None,
) -> ReportOut:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type not in ACCEPTED_TYPES:
        raise HTTPException(415, "send the raw message as message/rfc822")
    if reporter_email is not None and not _EMAIL.match(reporter_email):
        raise HTTPException(422, "reporter_email is not an email address")
    raw = await read_body_limited(request, MAX_MESSAGE_BYTES)
    if not raw.strip():
        raise HTTPException(422, "empty message")
    try:
        report = await run_in_threadpool(
            accept_submission,
            request.app,
            session,
            raw,
            source=ReportSource.API,
            reporter_email=reporter_email,
        )
    except QueueUnavailable as exc:
        raise HTTPException(503, "stored, but the queue is unavailable; try again later") from exc
    response.headers["Location"] = f"/api/reports/{report.id}"
    return ReportOut.of(report)


@router.get("/reports/{report_id}", dependencies=[Depends(require_api_token)])
def get_report(
    report_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]
) -> ReportOut:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "report not found")
    return ReportOut.of(report)
