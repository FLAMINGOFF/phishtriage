"""Shared fixtures. Tests never read the developer's environment, .env or network."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from app.config import (
    EXAMPLE_SETTINGS_FILE,
    SETTINGS_FILE_ENV,
    Policy,
    Settings,
    get_settings,
    load_policy_data,
)

# Variables Settings would pick up from the environment.
_SETTINGS_ENV = [name.upper() for name in Settings.model_fields] + [SETTINGS_FILE_ENV]


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _SETTINGS_ENV:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def example_policy() -> Policy:
    return Policy.model_validate(load_policy_data(EXAMPLE_SETTINGS_FILE))


@pytest.fixture
def make_settings(example_policy: Policy) -> Callable[..., Settings]:
    """Build Settings without touching .env; keyword arguments override fields."""

    def factory(**overrides: Any) -> Settings:
        overrides.setdefault("policy", example_policy)
        return Settings(_env_file=None, **overrides)

    return factory


# --------------------------------------------------------------------------- database


@pytest.fixture
def session_factory():
    """A fresh schema per test: SQLite in memory by default, PostgreSQL when
    TEST_DATABASE_URL is set (CI runs both)."""
    import os

    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import Base
    from app.db.session import make_engine

    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        engine = make_engine(url)
        Base.metadata.drop_all(engine)
    else:
        engine = create_engine(
            "sqlite+pysqlite://",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _foreign_keys(dbapi_connection, _record):  # pragma: no cover - trivial
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def store(tmp_path):
    from app.storage import BlobStore

    return BlobStore(tmp_path / "storage")


@pytest.fixture
def fixture_bytes():
    from pathlib import Path

    root = Path(__file__).parent / "fixtures" / "emails"

    def load(name: str) -> bytes:
        matches = sorted(root.glob(f"{name}*.eml"))
        assert matches, f"no fixture {name}"
        return matches[0].read_bytes()

    return load


# --------------------------------------------------------------------------- network, Redis


@pytest.fixture(autouse=True)
def http_mock():
    """Tests never reach the network: an httpx request without a matching route fails.

    Tests that exercise a provider client add routes to this router (``http_mock.get(...)``).
    """
    import respx

    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def fake_redis():
    from fakeredis import FakeRedis

    return FakeRedis()


# --------------------------------------------------------------------------- app and worker


@pytest.fixture
def worker_context(session_factory, store, fake_redis):
    """Build what the worker uses (app.jobs.WorkerContext) against the test resources."""
    from app.intel.service import build_intel_service
    from app.jobs import WorkerContext

    def factory(settings: Settings, intel: Any = None) -> WorkerContext:
        return WorkerContext(
            settings=settings,
            sessionmaker=session_factory,
            store=store,
            intel=intel if intel is not None else build_intel_service(settings, fake_redis),
        )

    return factory


@pytest.fixture
def app_factory(make_settings, session_factory, store, worker_context):
    """Build the FastAPI app against the test database and blob store.

    Unless a test passes its own ``enqueue``, a queued report is processed at once, in
    the request, by the same code the worker runs (app.jobs.run_report).
    """
    from app.jobs import run_report
    from app.main import create_app

    def factory(*, enqueue: Any = None, intel: Any = None, **overrides: Any):
        settings = make_settings(**overrides)
        context = worker_context(settings, intel)

        def run_now(report_id: Any) -> None:
            run_report(context, report_id)

        return create_app(
            settings,
            probes={},
            session_factory=session_factory,
            store=store,
            enqueue=enqueue or run_now,
        )

    return factory
