"""Report pages. M1 shows the parse results; M4 turns this into the full detail view."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db.models import Report
from app.web.deps import get_session
from app.web.templating import templates

router = APIRouter(tags=["reports"])


@router.get("/", include_in_schema=False)
def index() -> Response:
    return RedirectResponse("/upload", status_code=303)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_detail(
    request: Request, report_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]
) -> Response:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "report not found")
    return templates.TemplateResponse(request, "report.html", {"report": report})
