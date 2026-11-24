"""FastAPI dependencies shared by the routers: database, settings, login, CSRF."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import User
from app.storage import BlobStore
from app.web.auth import CSRF_FIELD, CSRF_HEADER, SessionStore, csrf_token, csrf_valid

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


def get_store(request: Request) -> BlobStore:
    store: BlobStore = request.app.state.store
    return store


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


async def read_body_limited(request: Request, limit: int) -> bytes:
    """Read the request body, refusing (413) anything over ``limit`` bytes.

    The declared Content-Length is checked first, and the stream is counted as it
    arrives, so a client that lies about (or omits) the length cannot exhaust memory.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"message larger than {limit:,} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"message larger than {limit:,} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- login


class LoginRequired(Exception):
    """Raised for console pages without a logged-in user; answered with a redirect."""

    def __init__(self, next_path: str) -> None:
        super().__init__(next_path)
        self.next_path = next_path


def browser_token(request: Request) -> str:
    token: str = request.state.browser_token
    return token


def login_url(next_path: str) -> str:
    return "/login?next=" + quote(next_path, safe="/")


def safe_next(value: str | None) -> str:
    """Only same-site paths: ``/reports``, never ``//evil.example`` or ``https://...``."""
    if not value or not value.startswith("/") or value.startswith(("//", "/\\")):
        return "/reports"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/reports"
    return value


def current_user(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> User | None:
    sessions: SessionStore = request.app.state.sessions
    user_id = sessions.user_id(browser_token(request))
    user = session.get(User, user_id) if user_id else None
    request.state.user = user
    return user


def require_user(request: Request, user: Annotated[User | None, Depends(current_user)]) -> User:
    if user is None:
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise LoginRequired(path)
    return user


def require_admin(user: Annotated[User, Depends(require_user)]) -> User:
    if not user.is_admin:
        raise HTTPException(403, "administrators only")
    return user


async def require_csrf(request: Request) -> None:
    """Unsafe methods need the CSRF token (form field or X-CSRF-Token header), else 403."""
    if request.method in SAFE_METHODS:
        return
    origin = request.headers.get("origin")
    # Host only (not the scheme): behind a TLS-terminating proxy the app itself sees http.
    if origin and urlsplit(origin).netloc != request.url.netloc:
        raise HTTPException(403, "cross-origin request refused")
    supplied = request.headers.get(CSRF_HEADER)
    if supplied is None and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        value = (await request.form()).get(CSRF_FIELD)
        supplied = value if isinstance(value, str) else None
    secret = request.app.state.settings.secret_key.get_secret_value()
    if not csrf_valid(secret, browser_token(request), supplied):
        raise HTTPException(403, "CSRF token missing or invalid")


def template_context(request: Request) -> dict[str, object]:
    """Jinja2 context processor: what every console page needs."""
    token = getattr(request.state, "browser_token", None)
    secret = request.app.state.settings.secret_key.get_secret_value()
    return {
        "csrf_token": csrf_token(secret, token) if token else "",
        "current_user": getattr(request.state, "user", None),
    }
