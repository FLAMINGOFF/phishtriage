"""Analyst console: login, sessions, CSRF, login throttling and the create-user command."""

from __future__ import annotations

import hashlib
import io
import uuid
from collections.abc import Callable

import pytest
from fakeredis import FakeRedis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import audit, cli
from app.db.models import AuditLog, User, UserRole
from app.web.auth import (
    ACCOUNT_LIMIT,
    ADDRESS_LIMIT,
    COOKIE_NAME,
    SECURE_COOKIE_NAME,
    LoginThrottle,
    SessionStore,
    csrf_token,
    csrf_valid,
    hash_password,
    is_token,
    needs_rehash,
    new_token,
    password_problem,
    verify_password,
)
from app.web.deps import safe_next
from tests.unit.console_helpers import TEST_PASSWORD, csrf, csrf_from, login

ANALYST = "analyst@example.edu"
REPORT = "/reports/00000000-0000-0000-0000-000000000000"


@pytest.fixture
def app(app_factory: Callable[..., FastAPI]) -> FastAPI:
    return app_factory()


@pytest.fixture
def browser(app: FastAPI) -> TestClient:
    """Not logged in, over https (the session cookie is Secure by default)."""
    return TestClient(app, base_url="https://testserver")


def audit_actions(session_factory) -> list[str]:
    with session_factory() as session:
        return list(session.scalars(select(AuditLog.action).order_by(AuditLog.created_at)))


# --------------------------------------------------------------------------- building blocks


def test_passwords() -> None:
    stored = hash_password(TEST_PASSWORD)
    assert stored.startswith("$argon2id$")
    assert TEST_PASSWORD not in stored
    assert verify_password(stored, TEST_PASSWORD)
    assert not verify_password(stored, TEST_PASSWORD + "x")
    assert not verify_password(None, TEST_PASSWORD)  # unknown account: same work, then no
    assert not verify_password("not a hash", TEST_PASSWORD)
    assert not needs_rehash(stored)
    assert password_problem("short", ANALYST) == "the password must have at least 12 characters"
    assert password_problem(ANALYST.upper(), ANALYST) == (
        "the password must not be the email address"
    )
    assert password_problem(TEST_PASSWORD, ANALYST) is None


def test_tokens_and_csrf() -> None:
    token = new_token()
    assert is_token(token)
    assert not is_token(None)
    assert not is_token("short")
    assert not is_token(token[:-1] + "!")
    secret = "s" * 40
    good = csrf_token(secret, token)
    assert csrf_valid(secret, token, good)
    assert not csrf_valid(secret, token, None)
    assert not csrf_valid(secret, token, "")
    assert not csrf_valid(secret, new_token(), good)  # bound to the browser's cookie
    assert not csrf_valid("t" * 40, token, good)  # and to the server's secret


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "/reports"),
        ("", "/reports"),
        ("/reports/abc?x=1", "/reports/abc?x=1"),
        ("//evil.example/", "/reports"),
        ("/\\evil.example", "/reports"),
        ("https://evil.example/", "/reports"),
        ("javascript:alert(1)", "/reports"),
        ("reports", "/reports"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected


def test_session_store_timeouts(fake_redis: FakeRedis) -> None:
    now = [1000.0]
    store = SessionStore(fake_redis, idle_seconds=600, max_age_seconds=3600, clock=lambda: now[0])
    user_id = uuid.uuid4()
    token = store.create(user_id)
    assert is_token(token)
    key = next(iter(fake_redis.scan_iter("session:*"))).decode()
    assert token not in key  # only a digest of the token is stored
    assert 0 < fake_redis.ttl(key) <= 600  # idle timeout
    assert store.user_id(token) == user_id
    assert store.user_id("x" * 43) is None
    assert store.user_id("not a token") is None

    now[0] += 3601  # absolute lifetime over, however active the session was
    assert store.user_id(token) is None
    assert not fake_redis.exists(key)

    token = store.create(user_id)
    store.delete(token)
    assert store.user_id(token) is None
    store.delete("not a token")  # ignored

    token = store.create(user_id)
    key = f"session:{hashlib.sha256(token.encode()).hexdigest()}"
    fake_redis.set(key, "junk")
    assert store.user_id(token) is None  # a corrupt entry is dropped, not trusted
    assert not fake_redis.exists(key)


def test_throttle_locks_account_and_address(fake_redis: FakeRedis) -> None:
    throttle = LoginThrottle(fake_redis)
    for _ in range(ACCOUNT_LIMIT.failures - 1):
        assert not throttle.failure(ANALYST, "192.0.2.1")
    assert not throttle.locked(ANALYST, "192.0.2.1")
    assert throttle.failure(ANALYST.upper(), "192.0.2.1")  # case does not matter
    assert throttle.locked(ANALYST, "198.51.100.7")  # the account, from any address
    assert not throttle.locked("other@example.edu", "198.51.100.7")

    # Password spraying: many accounts from one address lock that address.
    for n in range(ADDRESS_LIMIT.failures):
        throttle.failure(f"user{n}@example.edu", "203.0.113.5")
    assert throttle.locked("someone@example.edu", "203.0.113.5")

    # A success clears the account's failure count (but not an active lock).
    throttle.failure("bob@example.edu", "192.0.2.9")
    throttle.success("bob@example.edu")
    for _ in range(ACCOUNT_LIMIT.failures - 1):
        assert not throttle.failure("bob@example.edu", "192.0.2.9")


# --------------------------------------------------------------------------- login required


CONSOLE_PAGES = [
    "/",
    "/reports",
    "/reports?verdict=malicious",
    "/upload",
    "/audit",
    REPORT,
    f"{REPORT}/status",
    f"{REPORT}/body",
    f"{REPORT}/iocs.csv",
    f"{REPORT}/iocs.stix.json",
    f"{REPORT}/attachments/00000000-0000-0000-0000-000000000001",
    "/exports/iocs.csv",
    "/exports/iocs.stix.json",
]


@pytest.mark.parametrize("path", CONSOLE_PAGES)
def test_pages_redirect_to_login(browser: TestClient, path: str) -> None:
    response = browser.get(path, follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    page = browser.get(location)
    assert page.status_code == 200
    assert 'name="password"' in page.text
    assert csrf_from(page.text)


def test_login_redirect_keeps_the_page(browser: TestClient, make_user) -> None:
    make_user(ANALYST)
    response = browser.get("/reports?verdict=malicious&status=done", follow_redirects=False)
    assert (
        response.headers["location"] == "/login?next=/reports%3Fverdict%3Dmalicious%26status%3Ddone"
    )
    page = browser.get(response.headers["location"]).text
    assert 'name="next" value="/reports?verdict=malicious&amp;status=done"' in page
    response = browser.post(
        "/login",
        data={
            "email": ANALYST,
            "password": TEST_PASSWORD,
            "csrf_token": csrf_from(page),
            "next": "/reports?verdict=malicious&status=done",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/reports?verdict=malicious&status=done"


def test_htmx_poll_gets_a_redirect_header(browser: TestClient) -> None:
    response = browser.get(f"{REPORT}/status", headers={"HX-Request": "true"})
    assert response.status_code == 401
    assert response.headers["hx-redirect"].startswith("/login?next=")


def test_post_without_login_is_refused(browser: TestClient) -> None:
    token = csrf(browser)
    response = browser.post(
        f"{REPORT}/notes", data={"text": "hi", "csrf_token": token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_api_and_health_routes_set_no_cookie(browser: TestClient) -> None:
    assert "set-cookie" not in browser.get("/healthz").headers
    assert "set-cookie" not in browser.get("/api/reports/x").headers
    assert "set-cookie" not in browser.get("/static/app.css").headers


# --------------------------------------------------------------------------- login and logout


def test_login_success_rotates_the_token(
    browser: TestClient, make_user, session_factory, fake_redis: FakeRedis
) -> None:
    make_user(ANALYST)
    page = browser.get("/login")
    cookie = page.headers["set-cookie"]
    assert cookie.startswith(f"{SECURE_COOKIE_NAME}=")
    for attribute in ("Path=/", "HttpOnly", "SameSite=Lax", "Secure"):
        assert attribute in cookie
    before = browser.cookies[SECURE_COOKIE_NAME]
    assert not fake_redis.keys("session:*")  # a visitor has a cookie, not a session

    response = browser.post(
        "/login",
        data={
            "email": f"  {ANALYST.upper()} ",
            "password": TEST_PASSWORD,
            "csrf_token": csrf_from(page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/reports"
    after = browser.cookies[SECURE_COOKIE_NAME]
    assert after != before  # session fixation: a token planted before login is useless
    assert len(fake_redis.keys("session:*")) == 1

    page = browser.get("/reports")
    assert page.status_code == 200
    assert ANALYST in page.text  # shown in the navigation
    assert 'action="/logout"' in page.text
    with session_factory() as session:
        user = session.scalar(select(User).where(User.email == ANALYST))
        assert user is not None
        assert user.last_login_at is not None
    assert audit_actions(session_factory) == [audit.LOGIN_SUCCESS]

    # Already logged in: the login page sends the analyst on.
    response = browser.get("/login?next=/upload", follow_redirects=False)
    assert response.headers["location"] == "/upload"

    # The old (pre-login) token does not open the session.
    stale = TestClient(browser.app, base_url="https://testserver")
    stale.cookies.set(SECURE_COOKIE_NAME, before)
    assert stale.get("/reports", follow_redirects=False).status_code == 303


@pytest.mark.parametrize(
    ("email", "password"), [(ANALYST, "wrong password!!"), ("nobody@example.edu", TEST_PASSWORD)]
)
def test_login_failure_is_generic(
    browser: TestClient, make_user, session_factory, email: str, password: str
) -> None:
    make_user(ANALYST)
    response = browser.post(
        "/login", data={"email": email, "password": password, "csrf_token": csrf(browser)}
    )
    assert response.status_code == 401
    assert "Invalid email or password." in response.text  # same text: no account probing
    assert f'value="{email}"' in response.text  # the address is kept, the password is not
    assert password not in response.text
    assert audit_actions(session_factory) == [audit.LOGIN_FAILURE]


def test_five_failures_lock_the_account(
    browser: TestClient, make_user, session_factory, fake_redis: FakeRedis
) -> None:
    make_user(ANALYST)

    def attempt(password: str) -> int:
        data = {"email": ANALYST, "password": password, "csrf_token": csrf(browser)}
        return browser.post("/login", data=data).status_code

    assert [attempt("wrong password!!") for _ in range(4)] == [401] * 4
    assert attempt("wrong password!!") == 429  # the fifth failure locks
    response = browser.post(
        "/login", data={"email": ANALYST, "password": TEST_PASSWORD, "csrf_token": csrf(browser)}
    )
    assert response.status_code == 429  # even the right password, for 15 minutes
    assert "Too many failed attempts" in response.text
    lock = fake_redis.keys("login:lock:account:*")
    assert len(lock) == 1
    assert 0 < fake_redis.ttl(lock[0]) <= 15 * 60
    actions = audit_actions(session_factory)
    assert actions.count(audit.LOGIN_FAILURE) == 5
    assert actions[-1] == audit.LOGIN_LOCKED

    fake_redis.delete(*lock)  # 15 minutes later
    login(browser, ANALYST)


def test_logout_ends_the_session(
    app: FastAPI, console, fake_redis: FakeRedis, session_factory
) -> None:
    client = console(app)
    token = client.cookies[SECURE_COOKIE_NAME]
    page = client.get("/reports").text
    response = client.post("/logout", data={"csrf_token": csrf_from(page)}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert not fake_redis.keys("session:*")
    assert client.cookies[SECURE_COOKIE_NAME] != token
    assert client.get("/reports", follow_redirects=False).status_code == 303
    replay = TestClient(app, base_url="https://testserver")
    replay.cookies.set(SECURE_COOKIE_NAME, token)
    assert replay.get("/reports", follow_redirects=False).status_code == 303
    assert audit_actions(session_factory)[-1] == audit.LOGOUT


def test_insecure_cookie_for_the_local_demo(app_factory: Callable[..., FastAPI], make_user) -> None:
    make_user(ANALYST)
    client = TestClient(app_factory(session_cookie_secure=False))  # plain http
    cookie = client.get("/login").headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert "Secure" not in cookie
    assert "HttpOnly" in cookie
    login(client, ANALYST)
    assert client.get("/reports").status_code == 200


def test_production_requires_secure_cookies(make_settings) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE must be true"):
        make_settings(app_env="prod", secret_key="s" * 40, session_cookie_secure=False)


def test_deleted_user_loses_access(app: FastAPI, console, session_factory) -> None:
    client = console(app)
    with session_factory() as session:
        session.delete(session.scalar(select(User).where(User.email == ANALYST)))
        session.commit()
    assert client.get("/reports", follow_redirects=False).status_code == 303


# --------------------------------------------------------------------------- CSRF


def test_post_without_csrf_token_is_403(app: FastAPI, console, session_factory) -> None:
    client = console(app)
    for path, data in [
        ("/logout", {}),
        ("/upload", {}),
        (f"{REPORT}/notes", {"text": "hello"}),
        (f"{REPORT}/verdict", {"verdict": "malicious"}),
        (f"{REPORT}/requeue", {}),
    ]:
        response = client.post(path, data=data, follow_redirects=False)
        assert response.status_code == 403, path
        assert response.json() == {"detail": "CSRF token missing or invalid"}
        response = client.post(path, data={**data, "csrf_token": "0" * 64}, follow_redirects=False)
        assert response.status_code == 403, path


def test_login_needs_csrf_token(browser: TestClient, make_user) -> None:
    make_user(ANALYST)
    response = browser.post("/login", data={"email": ANALYST, "password": TEST_PASSWORD})
    assert response.status_code == 403


def test_csrf_token_of_another_browser_is_refused(app: FastAPI, console) -> None:
    client = console(app)
    other = TestClient(app, base_url="https://testserver")
    stolen = csrf(other)  # valid, but for a different cookie
    response = client.post(f"{REPORT}/notes", data={"text": "x", "csrf_token": stolen})
    assert response.status_code == 403


def test_csrf_header_and_origin(app: FastAPI, console) -> None:
    client = console(app)
    token = csrf(client, "/reports")
    # htmx sends the token as a header; then the request reaches the route (404: no report).
    response = client.post(f"{REPORT}/notes", data={"text": "x"}, headers={"X-CSRF-Token": token})
    assert response.status_code == 404
    response = client.post(
        f"{REPORT}/notes",
        data={"text": "x", "csrf_token": token},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "cross-origin request refused"}
    response = client.post(
        f"{REPORT}/notes",
        data={"text": "x", "csrf_token": token},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 404
    # "null" is what a sandboxed frame (or a no-referrer page) sends: refused as well.
    # The console's Referrer-Policy is same-origin so that real forms send their origin.
    response = client.post(
        f"{REPORT}/notes", data={"text": "x", "csrf_token": token}, headers={"Origin": "null"}
    )
    assert response.status_code == 403


def test_pages_carry_the_csrf_token(app: FastAPI, console) -> None:
    client = console(app)
    page = client.get("/upload").text
    token = csrf_from(page)
    assert f'hx-headers=\'{{"X-CSRF-Token": "{token}"}}\'' in page


# --------------------------------------------------------------------------- roles


def test_audit_page_is_for_administrators(app: FastAPI, console, session_factory) -> None:
    analyst = console(app)
    assert analyst.get("/audit").status_code == 403
    assert "Audit log" not in analyst.get("/reports").text

    admin = console(app, email="admin@example.edu", role="admin")
    assert 'href="/audit"' in admin.get("/reports").text
    page = admin.get("/audit")
    assert page.status_code == 200
    assert "login.success" in page.text
    assert ANALYST in page.text
    filtered = admin.get("/audit", params={"action": "logout"}).text
    assert "login.success</code>" not in filtered
    by_user = admin.get("/audit", params={"user": "ADMIN@example.edu"}).text
    assert "admin@example.edu" in by_user
    assert f"<td>{ANALYST}</td>" not in by_user
    assert admin.get("/audit", params={"action": "bogus", "page": 99}).status_code == 200


# --------------------------------------------------------------------------- create-user


@pytest.fixture
def cli_database(monkeypatch: pytest.MonkeyPatch, session_factory):
    import app.db.session

    monkeypatch.setattr(app.db.session, "get_sessionmaker", lambda: session_factory)
    return session_factory


def run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str], stdin: str) -> tuple[int, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    out = io.StringIO()
    return cli.main(argv, out=out), out.getvalue()


def test_create_user(monkeypatch: pytest.MonkeyPatch, cli_database, capsys) -> None:
    code, out = run_cli(
        monkeypatch,
        ["create-user", "Admin@Example.edu", "--role", "admin", "--password-stdin"],
        TEST_PASSWORD + "\n",
    )
    assert (code, out) == (0, "created admin admin@example.edu\n")
    with cli_database() as session:
        user = session.scalar(select(User))
        assert user is not None
        assert (user.email, user.role) == ("admin@example.edu", UserRole.ADMIN)
        assert verify_password(user.password_hash, TEST_PASSWORD)

    code, _ = run_cli(
        monkeypatch, ["create-user", "admin@example.edu", "--password-stdin"], TEST_PASSWORD
    )
    assert code == 1
    assert "already exists" in capsys.readouterr().err

    code, out = run_cli(
        monkeypatch,
        ["create-user", "admin@example.edu", "--password-stdin", "--update"],
        "another long password\n",
    )
    assert (code, out) == (0, "updated analyst admin@example.edu\n")
    with cli_database() as session:
        user = session.scalar(select(User))
        assert user is not None
        assert user.role is UserRole.ANALYST
        assert verify_password(user.password_hash, "another long password")


@pytest.mark.parametrize(
    ("argv", "stdin", "message"),
    [
        (["create-user", "not-an-address", "--password-stdin"], TEST_PASSWORD, "not an email"),
        (["create-user", "a@example.edu", "--password-stdin"], "short\n", "at least 12"),
        (["create-user", "a@example.edu", "--password-stdin"], "a@example.edu", "email address"),
    ],
)
def test_create_user_rejects(
    monkeypatch: pytest.MonkeyPatch, cli_database, capsys, argv, stdin, message
) -> None:
    code, _ = run_cli(monkeypatch, argv, stdin)
    assert code == 2
    assert message in capsys.readouterr().err
    with cli_database() as session:
        assert session.scalar(select(User)) is None


def test_create_user_prompts_twice(monkeypatch: pytest.MonkeyPatch, cli_database, capsys) -> None:
    answers = iter([TEST_PASSWORD, "something else entirely"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["create-user", "a@example.edu"], out=io.StringIO()) == 2
    assert "do not match" in capsys.readouterr().err
    answers = iter([TEST_PASSWORD, TEST_PASSWORD])
    assert cli.main(["create-user", "a@example.edu"], out=io.StringIO()) == 0
