"""REST API, web upload, report page and the HTTP security middleware."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web.security import CONTENT_SECURITY_POLICY

TOKEN = "t" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}
RFC822 = {"Content-Type": "message/rfc822"}
Loader = Callable[[str], bytes]


@pytest.fixture
def client(app_factory: Callable[..., FastAPI]) -> TestClient:
    return TestClient(app_factory(api_token=TOKEN))


def test_api_disabled_without_token(app_factory: Callable[..., FastAPI]) -> None:
    client = TestClient(app_factory())
    response = client.post("/api/reports", content=b"x", headers={**AUTH, **RFC822})
    assert response.status_code == 403


@pytest.mark.parametrize(
    "authorization", [None, "Bearer wrong", f"Basic {TOKEN}", f"Bearer {TOKEN}x", "Bearer"]
)
def test_api_requires_the_token(client: TestClient, authorization: str | None) -> None:
    headers = dict(RFC822)
    if authorization is not None:
        headers["Authorization"] = authorization
    response = client.post("/api/reports", content=b"x", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_api_rejects_wrong_type_and_bad_input(client: TestClient) -> None:
    assert client.post("/api/reports", content=b"x", headers=AUTH).status_code == 415
    response = client.post(
        "/api/reports", content=b"x", headers={**AUTH, "Content-Type": "application/json"}
    )
    assert response.status_code == 415
    response = client.post("/api/reports", content=b"  \r\n", headers={**AUTH, **RFC822})
    assert response.status_code == 422
    response = client.post(
        "/api/reports?reporter_email=not-an-address", content=b"x", headers={**AUTH, **RFC822}
    )
    assert response.status_code == 422


def test_api_create_and_get(client: TestClient, fixture_bytes: Loader) -> None:
    response = client.post(
        "/api/reports?reporter_email=Alice@Example.edu",
        content=fixture_bytes("08"),
        headers={**AUTH, "Content-Type": "message/rfc822; charset=utf-8"},
    )
    assert response.status_code == 202, response.text
    accepted = response.json()
    assert accepted["status"] == "queued"  # the worker does the analysis
    assert accepted["source"] == "api"
    assert response.headers["location"] == f"/api/reports/{accepted['id']}"

    # The test app's queue runs the job at once, so the report is already processed.
    response = client.get(response.headers["location"], headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == accepted["id"]
    assert body["status"] == "done"
    assert body["intake_mode"] == "attachment"
    assert len(body["related"]) == 1  # two originals attached: one extra report
    assert body["verdict"] == "no_issues"
    assert body["score"] == 0

    child_id = body["related"][0]
    child = client.get(f"/api/reports/{child_id}", headers=AUTH).json()
    assert child["parent_id"] == body["id"]
    assert child["verdict"] == "suspicious"
    assert {f["rule_id"] for f in child["findings"]} >= {"ATT_HTML_FILE", "URL_PUNYCODE"}
    # No intel keys in tests: every lookup is listed as skipped, with the reason.
    intel = [i for o in child["observables"] for i in o["intel"]]
    assert intel
    assert {i["status"] for i in intel} == {"skipped"}
    assert any("VT_API_KEY" in (i["detail"] or "") for i in intel)

    assert client.get(f"/api/reports/{body['id']}").status_code == 401
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/reports/{missing}", headers=AUTH).status_code == 404
    assert client.get("/api/reports/not-a-uuid", headers=AUTH).status_code == 422


def test_api_rejected_message_is_reported(client: TestClient) -> None:
    response = client.post("/api/reports", content=b"\x00\x01junk", headers={**AUTH, **RFC822})
    assert response.status_code == 202
    report = client.get(response.headers["location"], headers=AUTH).json()
    assert report["status"] == "failed"
    assert report["error"].startswith("rejected: ")


def test_queue_unavailable(
    app_factory: Callable[..., FastAPI], fixture_bytes: Loader, session_factory
) -> None:
    from app.db.models import Report, ReportStatus
    from app.queueing import QueueUnavailable

    def broken(_report_id: object) -> None:
        raise QueueUnavailable("connection refused")

    client = TestClient(app_factory(api_token=TOKEN, enqueue=broken))
    response = client.post("/api/reports", content=fixture_bytes("01"), headers={**AUTH, **RFC822})
    assert response.status_code == 503
    response = client.post("/upload", files={"file": ("x.eml", fixture_bytes("01"))})
    assert response.status_code == 503
    assert "could not be queued" in response.text
    with session_factory() as session:
        reports = session.query(Report).all()
    assert len(reports) == 2  # stored, so nothing is lost; `app.cli requeue` retries them
    assert {r.status for r in reports} == {ReportStatus.FAILED}
    assert all("could not be queued" in (r.error or "") for r in reports)


def test_report_page_polls_until_done(
    app_factory: Callable[..., FastAPI], fixture_bytes: Loader, make_settings, worker_context
) -> None:
    from app.jobs import run_report

    queued: list[object] = []
    client = TestClient(app_factory(enqueue=queued.append))
    response = client.post(
        "/upload", files={"file": ("x.eml", fixture_bytes("02"))}, follow_redirects=False
    )
    location = response.headers["location"]
    page = client.get(location).text
    assert "Waiting in the queue" in page
    assert f'hx-get="{location}/status"' in page
    status = client.get(f"{location}/status")
    assert status.status_code == 200
    assert "HX-Refresh" not in status.headers
    assert 'hx-trigger="every 2s"' in status.text

    assert len(queued) == 1
    run_report(worker_context(make_settings()), queued[0])  # the worker picks it up

    status = client.get(f"{location}/status")
    assert status.headers["hx-refresh"] == "true"
    page = client.get(location).text
    assert "Waiting in the queue" not in page
    assert "Malicious" in page
    assert "Not looked up:" in page
    assert client.get("/reports/00000000-0000-0000-0000-000000000000/status").status_code == 404


def test_api_body_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.ingest.api as api

    monkeypatch.setattr(api, "MAX_MESSAGE_BYTES", 100)
    response = client.post("/api/reports", content=b"x" * 101, headers={**AUTH, **RFC822})
    assert response.status_code == 413

    def chunks():  # no Content-Length: the stream itself is counted
        for _ in range(5):
            yield b"x" * 50

    response = client.post("/api/reports", content=chunks(), headers={**AUTH, **RFC822})
    assert response.status_code == 413


def test_middleware_limit_applies_to_every_route(app_factory: Callable[..., FastAPI]) -> None:
    from app.web.security import BodySizeLimitMiddleware

    app = app_factory(api_token=TOKEN)
    app.user_middleware = [m for m in app.user_middleware if m.cls is not BodySizeLimitMiddleware]
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=10)
    client = TestClient(app)
    response = client.post("/upload", files={"file": ("a.eml", b"x" * 100)})
    assert response.status_code == 413

    def chunks():
        yield b"x" * 8
        yield b"x" * 8

    response = client.post("/api/reports", content=chunks(), headers={**AUTH, **RFC822})
    assert response.status_code == 413


def test_upload_flow(client: TestClient, fixture_bytes: Loader) -> None:
    form = client.get("/upload")
    assert form.status_code == 200
    assert 'enctype="multipart/form-data"' in form.text

    response = client.post(
        "/upload",
        files={"file": ("x.eml", fixture_bytes("02"), "message/rfc822")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/reports/")

    page = client.get(location)
    assert page.status_code == 200
    assert "Mailbox quota exceeded" in page.text
    assert "[.]" in page.text  # indicators are shown defanged
    assert "Malicious" in page.text
    assert "AUTH_DMARC_FAIL" in page.text
    assert "DMARC failed in a trusted Authentication-Results header." in page.text
    assert "https://account-verify" not in page.text  # evidence is defanged too
    assert "<script" not in page.text.split("</head>", 1)[1].replace(
        '<script src="/static/vendor/htmx-2.0.11.min.js" defer></script>', ""
    )


def test_upload_empty_file(client: TestClient) -> None:
    response = client.post("/upload", files={"file": ("x.eml", b"   ")})
    assert response.status_code == 422
    assert "The file is empty." in response.text


def test_report_page_escapes_hostile_content(client: TestClient) -> None:
    hostile = (
        b'From: "<script>alert(1)</script>" <a@evil.example>\r\n'
        b"Subject: <img src=x onerror=alert(2)>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"</pre><script>alert(3)</script> safe\xe2\x80\xae\r\n"
    )
    response = client.post("/upload", files={"file": ("x.eml", hostile)}, follow_redirects=False)
    page = client.get(response.headers["location"]).text
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=alert(2)&gt;" in page


def test_report_page_404_and_index(client: TestClient) -> None:
    assert client.get("/reports/00000000-0000-0000-0000-000000000000").status_code == 404
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/upload"


def test_security_headers(client: TestClient) -> None:
    response = client.get("/upload")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
    static = client.get("/static/app.css")
    assert static.status_code == 200
    assert "max-age" in static.headers["cache-control"]
    assert static.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_docs_only_in_dev(app_factory: Callable[..., FastAPI]) -> None:
    dev = TestClient(app_factory(app_env="dev"))
    assert dev.get("/docs").status_code == 200
    assert "content-security-policy" not in dev.get("/docs").headers
    prod = TestClient(
        app_factory(app_env="prod", secret_key="s" * 40, imap_ssl=True, api_token=TOKEN)
    )
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404
