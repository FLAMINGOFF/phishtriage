"""HTTP-level protections applied to every response and request."""

from __future__ import annotations

from collections.abc import Iterable

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.web.auth import is_token, new_token

# 'self' only: scripts and styles are vendored (app/web/static/vendor), no inline code,
# no CDN. Pico's form icons are data: SVGs, hence img-src data:.
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "frame-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'none'",
        "object-src 'none'",
    ]
)

SECURITY_HEADERS = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    # same-origin, not no-referrer: under no-referrer browsers send "Origin: null" with
    # every form POST, and the CSRF check (app.web.deps.require_csrf) refuses a foreign
    # or null Origin. Nothing is ever sent to other sites either way.
    "referrer-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cross-origin-opener-policy": "same-origin",
    "cache-control": "no-store",
}


class SecurityHeadersMiddleware:
    """Add security headers unless the route already set its own (e.g. a stricter CSP)."""

    def __init__(self, app: ASGIApp, exempt_prefixes: Iterable[str] = ()) -> None:
        self.app = app
        self.exempt = tuple(exempt_prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (self.exempt and scope["path"].startswith(self.exempt)):
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    if name not in headers:
                        headers[name] = value
                if scope["path"].startswith("/static/"):
                    headers["cache-control"] = "public, max-age=3600"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Reject request bodies over ``max_bytes`` (413) before any handler buffers them."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > self.max_bytes:
                await self._reject(send)
                return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(413, "request body too large")
            return message

        await self.app(scope, limited_receive, send)

    async def _reject(self, send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class BrowserCookieMiddleware:
    """Give every console visitor the session cookie and keep it in ``request.state``.

    The cookie holds an opaque random token. Before login it only anchors the CSRF token;
    after login the same name carries the session token (see app.web.auth). A route that
    logs a user in or out puts the replacement in ``request.state.set_browser_token``.
    API, health and static routes are left alone: they never use cookies.
    """

    SKIP_PREFIXES = ("/api/", "/static/", "/healthz", "/readyz")

    def __init__(self, app: ASGIApp, cookie_name: str, secure: bool) -> None:
        self.app = app
        self.cookie_name = cookie_name
        self.secure = secure

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].startswith(self.SKIP_PREFIXES):
            await self.app(scope, receive, send)
            return
        cookie = Request(scope).cookies.get(self.cookie_name)
        issued = not is_token(cookie)
        token: str = new_token() if issued or cookie is None else cookie
        state = scope.setdefault("state", {})
        state["browser_token"] = token

        async def send_with_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                replacement: str | None = state.get("set_browser_token")
                if replacement or issued:
                    MutableHeaders(scope=message).append(
                        "set-cookie", self._cookie(replacement or token)
                    )
            await send(message)

        await self.app(scope, receive, send_with_cookie)

    def _cookie(self, value: str) -> str:
        # No Max-Age: the browser forgets it on exit; the server-side session expires anyway.
        attributes = [f"{self.cookie_name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if self.secure:
            attributes.append("Secure")
        return "; ".join(attributes)
