"""Worker wiring, database helpers, migrations and project metadata."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fakeredis import FakeRedis
from rq.serializers import JSONSerializer
from sqlalchemy import inspect

from app import __version__, worker
from app.config import EXAMPLE_SETTINGS_FILE, SETTINGS_FILE_ENV
from app.db.models import Base
from app.db.session import make_engine, ping_database

ROOT = Path(__file__).resolve().parents[2]


def test_worker_listens_on_reports_queue_with_json() -> None:
    conn = FakeRedis()
    built = worker.build_worker(conn)
    assert built.queue_names() == ["reports"]
    assert worker.get_queue(conn).serializer is JSONSerializer


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
    assert "alembic_version" in tables


def test_version_matches_pyproject() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == __version__
