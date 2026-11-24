"""Worker wiring, database helpers, migrations and project metadata."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fakeredis import FakeRedis
from rq.serializers import JSONSerializer
from sqlalchemy import inspect, text

from app import __version__, queueing, worker
from app.config import EXAMPLE_SETTINGS_FILE, SETTINGS_FILE_ENV
from app.db.models import Base
from app.db.session import make_engine, ping_database

ROOT = Path(__file__).resolve().parents[2]


def test_worker_listens_on_reports_queue_with_json() -> None:
    conn = FakeRedis()
    built = worker.build_worker(conn)
    assert built.queue_names() == ["reports"]
    assert queueing.get_queue(conn).serializer is JSONSerializer


def test_make_engine_sets_connect_timeout_for_postgres() -> None:
    engine = make_engine("postgresql+psycopg://u:p@localhost/db")
    assert engine.dialect.name == "postgresql"
    assert engine.pool._pre_ping


def test_ping_database_with_sqlite() -> None:
    ping_database(make_engine("sqlite://"))


def test_ping_database_failure() -> None:
    engine = make_engine("sqlite:////nonexistent-dir/x.db")
    with pytest.raises(Exception, match="unable to open"):
        ping_database(engine)


def test_metadata_has_naming_convention() -> None:
    assert Base.metadata.naming_convention["pk"] == "pk_%(table_name)s"


def test_alembic_upgrade_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "migrate.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv(SETTINGS_FILE_ENV, str(EXAMPLE_SETTINGS_FILE))
    monkeypatch.chdir(tmp_path)  # make sure no developer .env is read
    cfg = Config(str(ROOT / "alembic.ini"))
    command.upgrade(cfg, "head")
    tables = inspect(make_engine(f"sqlite:///{db}")).get_table_names()
    assert {"alembic_version", "reports", "emails", "attachments", "observables"} <= set(tables)
    command.check(cfg)  # the models and the migrations describe the same schema
    command.downgrade(cfg, "base")
    assert inspect(make_engine(f"sqlite:///{db}")).get_table_names() == ["alembic_version"]


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="needs PostgreSQL")
def test_alembic_round_trip_on_postgres(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from app.db.models import Base

    url = os.environ["TEST_DATABASE_URL"]
    engine = make_engine(url)
    Base.metadata.drop_all(engine)  # tables left by the ORM tests
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv(SETTINGS_FILE_ENV, str(EXAMPLE_SETTINGS_FILE))
    monkeypatch.chdir(tmp_path)
    cfg = Config(str(ROOT / "alembic.ini"))
    command.upgrade(cfg, "head")
    try:
        command.check(cfg)
    finally:
        command.downgrade(cfg, "base")
        engine.dispose()


def test_version_matches_pyproject() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == __version__
