"""IOC export: CSV and STIX 2.1, for one report or for recent reports by verdict.

Exports are downloads (GET) and every one is written to the audit log: who exported
which indicators, when. Values are exported as they were seen (not defanged) because
the consumers are blocklists and threat-intel platforms; the CSV also carries the
defanged form for humans.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.orm.interfaces import LoaderOption

from app import audit
from app.db.models import Observable, Report, ReportStatus, User, Verdict, utcnow
from app.export.csv_export import to_csv
from app.export.iocs import ioc_rows
from app.export.stix_export import to_stix_bundle
from app.web.deps import get_session, require_user
from app.web.routes.reports import final_verdict_column

router = APIRouter(tags=["exports"], dependencies=[Depends(require_user)])

STIX_MEDIA_TYPE = "application/stix+json;version=2.1"
DEFAULT_EXPORT_VERDICTS = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
MAX_EXPORT_DAYS = 365
MAX_EXPORT_REPORTS = 5000

CurrentUser = Annotated[User, Depends(require_user)]
DbSession = Annotated[Session, Depends(get_session)]


def _with_indicators() -> LoaderOption:
    return selectinload(Report.observables).selectinload(Observable.intel_results)


def _one_report(session: Session, report_id: uuid.UUID) -> list[Report]:
    report = session.scalar(
        select(Report).where(Report.id == report_id).options(_with_indicators())
    )
    if report is None:
        raise HTTPException(404, "report not found")
    return [report]


def _recent_reports(session: Session, verdicts: Sequence[Verdict], days: int) -> list[Report]:
    since = utcnow() - timedelta(days=days)
    return list(
        session.scalars(
            select(Report)
            .where(
                Report.status == ReportStatus.DONE,
                Report.received_at >= since,
                final_verdict_column().in_(list(verdicts)),
            )
            .order_by(Report.received_at.desc())
            .limit(MAX_EXPORT_REPORTS)
            .options(_with_indicators())
        )
    )


def _download(body: str, media_type: str, filename: str) -> Response:
    return Response(
        body,
        media_type=media_type,
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


def _export(
    session: Session,
    user: User,
    reports: list[Report],
    fmt: str,
    filename: str,
    *,
    report_id: uuid.UUID | None = None,
    **scope: object,
) -> Response:
    rows = ioc_rows(reports)
    if fmt == "csv":
        body, media_type, action = to_csv(rows), "text/csv; charset=utf-8", audit.EXPORT_CSV
    else:
        body = to_stix_bundle(rows).serialize(pretty=True)
        media_type, action = STIX_MEDIA_TYPE, audit.EXPORT_STIX
    audit.record(
        session,
        action,
        user=user,
        report_id=report_id,
        reports=len(reports),
        indicators=len(rows),
        **scope,
    )
    session.commit()
    return _download(body, media_type, filename)


@router.get("/reports/{report_id}/iocs.csv")
def report_csv(report_id: uuid.UUID, session: DbSession, user: CurrentUser) -> Response:
    reports = _one_report(session, report_id)
    return _export(
        session, user, reports, "csv", f"phishtriage-{report_id}.csv", report_id=report_id
    )


@router.get("/reports/{report_id}/iocs.stix.json")
def report_stix(report_id: uuid.UUID, session: DbSession, user: CurrentUser) -> Response:
    reports = _one_report(session, report_id)
    return _export(
        session, user, reports, "stix", f"phishtriage-{report_id}.stix.json", report_id=report_id
    )


def _bulk(
    session: Session, user: User, fmt: str, verdict: list[Verdict] | None, days: int
) -> Response:
    verdicts = sorted(set(verdict or DEFAULT_EXPORT_VERDICTS))
    reports = _recent_reports(session, verdicts, days)
    stamp = utcnow().strftime("%Y%m%d")
    extension = "csv" if fmt == "csv" else "stix.json"
    return _export(
        session,
        user,
        reports,
        fmt,
        f"phishtriage-iocs-{stamp}.{extension}",
        verdicts=[v.value for v in verdicts],
        days=days,
    )


VerdictQuery = Annotated[list[Verdict] | None, Query()]
DaysQuery = Annotated[int, Query(ge=1, le=MAX_EXPORT_DAYS)]


@router.get("/exports/iocs.csv")
def bulk_csv(
    session: DbSession, user: CurrentUser, verdict: VerdictQuery = None, days: DaysQuery = 30
) -> Response:
    return _bulk(session, user, "csv", verdict, days)


@router.get("/exports/iocs.stix.json")
def bulk_stix(
    session: DbSession, user: CurrentUser, verdict: VerdictQuery = None, days: DaysQuery = 30
) -> Response:
    return _bulk(session, user, "stix", verdict, days)
