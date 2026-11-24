"""Login and logout for the analyst console."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db.models import User, utcnow
from app.web.auth import (
    LoginThrottle,
    SessionStore,
    hash_password,
    needs_rehash,
    new_token,
    verify_password,
)
from app.web.deps import browser_token, current_user, get_session, require_csrf, safe_next
from app.web.templating import templates

router = APIRouter(tags=["auth"])

GENERIC_FAILURE = "Invalid email or password."
LOCKED = "Too many failed attempts. Try again in 15 minutes."


def client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/login", response_class=HTMLResponse)
def login_form(
    request: Request,
    user: Annotated[User | None, Depends(current_user)],
    next: str | None = None,
) -> Response:
    if user is not None:
        return RedirectResponse(safe_next(next), status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"error": None, "email": "", "next": safe_next(next)}
    )


@router.post("/login", dependencies=[Depends(require_csrf)])
async def login(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    email: Annotated[str, Form(max_length=320)],
    password: Annotated[str, Form(max_length=1024)],
    next: Annotated[str, Form(max_length=2048)] = "/reports",
) -> Response:
    email = email.strip().lower()
    throttle: LoginThrottle = request.app.state.login_throttle
    address = client_address(request)

    def fail(message: str, status: int) -> Response:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": message, "email": email, "next": safe_next(next)},
            status_code=status,
        )

    if throttle.locked(email, address):
        audit.record(session, audit.LOGIN_LOCKED, email=email, ip=address)
        session.commit()
        return fail(LOCKED, 429)

    user = session.scalar(select(User).where(User.email == email))
    # argon2 is deliberately slow: keep it off the event loop.
    ok = await run_in_threadpool(verify_password, user.password_hash if user else None, password)
    if not ok or user is None:
        locked_now = throttle.failure(email, address)
        audit.record(session, audit.LOGIN_FAILURE, user=user, email=email, ip=address)
        session.commit()
        return fail(LOCKED if locked_now else GENERIC_FAILURE, 429 if locked_now else 401)

    throttle.success(email)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = utcnow()
    sessions: SessionStore = request.app.state.sessions
    # A fresh token on login: a token planted before login (session fixation) is useless.
    request.state.set_browser_token = sessions.create(user.id)
    audit.record(session, audit.LOGIN_SUCCESS, user=user, ip=address)
    session.commit()
    return RedirectResponse(safe_next(next), status_code=303)


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    user: Annotated[User | None, Depends(current_user)],
) -> Response:
    sessions: SessionStore = request.app.state.sessions
    sessions.delete(browser_token(request))
    request.state.set_browser_token = new_token()
    if user is not None:
        audit.record(session, audit.LOGOUT, user=user, ip=client_address(request))
        session.commit()
    return RedirectResponse("/login", status_code=303)
