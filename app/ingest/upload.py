"""Web upload of a single .eml file from the analyst console."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db.models import ReportSource
from app.ingest.submission import accept_submission
from app.parsing.eml import MAX_MESSAGE_BYTES
from app.queueing import QueueUnavailable
from app.web.deps import get_session
from app.web.templating import templates

router = APIRouter(tags=["upload"])


@router.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "upload.html", {"error": None})


@router.post("/upload")
async def upload(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    file: Annotated[UploadFile, File()],
) -> Response:
    raw = await file.read(MAX_MESSAGE_BYTES + 1)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise HTTPException(413, f"message larger than {MAX_MESSAGE_BYTES:,} bytes")
    if not raw.strip():
        return templates.TemplateResponse(
            request, "upload.html", {"error": "The file is empty."}, status_code=422
        )
    try:
        report = await run_in_threadpool(
            accept_submission, request.app, session, raw, source=ReportSource.UPLOAD
        )
    except QueueUnavailable:
        return templates.TemplateResponse(
            request,
            "upload.html",
            {"error": "The file was stored but could not be queued. Please try again later."},
            status_code=503,
        )
    return RedirectResponse(f"/reports/{report.id}", status_code=303)
