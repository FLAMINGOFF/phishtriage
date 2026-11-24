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
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "done"
    assert body["source"] == "api"
    assert body["intake_mode"] == "attachment"
    assert len(body["related"]) == 1  # two originals attached: one extra report

    child_id = body["related"][0]
    child = client.get(f"/api/reports/{child_id}", headers=AUTH).json()
    assert child["verdict"] == "suspicious"
    assert {f["rule_id"] for f in child["findings"]} >= {"ATT_HTML_FILE", "URL_PUNYCODE"}
    assert body["verdict"] == "no_issues"
    assert body["score"] == 0

    response = client.get(f"/api/reports/{body['id']}", headers=AUTH)
    assert response.status_code == 200
    assert response.json()["id"] == body["id"]
    child = client.get(f"/api/reports/{body['related'][0]}", headers=AUTH).json()
    assert child["parent_id"] == body["id"]

    assert client.get(f"/api/reports/{body['id']}").status_code == 401
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/reports/{missing}", headers=AUTH).status_code == 404
    assert client.get("/api/reports/not-a-uuid", headers=AUTH).status_code == 422


def test_api_rejected_message_is_reported(client: TestClient) -> None:
    response = client.post("/api/reports", content=b"\x00\x01junk", headers={**AUTH, **RFC822})
    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json()["error"].startswith("rejected: ")


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
