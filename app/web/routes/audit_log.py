"""The audit log page: administrators only."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.db.models import AuditLog, User
from app.web.deps import get_session, require_admin
from app.web.templating import templates

router = APIRouter(tags=["audit"], dependencies=[Depends(require_admin)])

PAGE_SIZE = 100


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    action: str = "",
    user: Annotated[str, Query(max_length=320)] = "",
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
) -> Response:
    conditions: list[ColumnElement[bool]] = []
    if action in audit.ACTIONS:
        conditions.append(AuditLog.action == action)
    else:
        action = ""
    email = user.strip().lower()
    if email:
        conditions.append(AuditLog.user.has(User.email == email))
    total = session.scalar(select(func.count()).select_from(AuditLog).where(*conditions)) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(page, pages)
    entries = session.scalars(
        select(AuditLog)
        .where(*conditions)
        .options(selectinload(AuditLog.user))
        .order_by(AuditLog.created_at.desc(), AuditLog.id)
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    filters = {"action": action, "user": email}
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "entries": entries,
            "total": total,
            "page": page,
            "pages": pages,
            "filters": filters,
            "query": {k: v for k, v in filters.items() if v},
            "actions": audit.ACTIONS,
        },
    )
