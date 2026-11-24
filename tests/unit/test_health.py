from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.main import create_app, default_probes


def ok() -> None:
    return None


def broken() -> None:
    raise ConnectionError("db.internal:5432 refused connection for user phishtriage")


@pytest.fixture
def client_factory(make_settings):
    def factory(probes=None, **settings):
        app = create_app(make_settings(**settings), probes=probes if probes is not None else {})
        return TestClient(app)

    return factory


def test_healthz_is_always_ok(client_factory) -> None:
    client = client_factory(probes={"database": broken})
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_ok_when_all_probes_pass(client_factory) -> None:
    client = client_factory(probes={"database": ok, "redis": ok})
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}


def test_readyz_503_without_leaking_details(client_factory) -> None:
    client = client_factory(probes={"database": broken, "redis": ok})
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "error", "checks": {"database": "error", "redis": "ok"}}
    assert "db.internal" not in response.text


def test_api_docs_only_in_dev(client_factory) -> None:
    assert client_factory(app_env="dev").get("/docs").status_code == 200
    prod = client_factory(app_env="prod", secret_key="k" * 40, imap_ssl=True)
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404


def test_default_probes_cover_database_and_redis(make_settings) -> None:
    assert set(default_probes(make_settings())) == {"database", "redis"}


def test_health_endpoints_do_not_advertise_version(client_factory) -> None:
    client = client_factory(probes={"redis": ok})
    for path in ("/healthz", "/readyz"):
        assert __version__ not in client.get(path).text
