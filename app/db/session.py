"""Engine and session factory."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

CONNECT_TIMEOUT_SECONDS = 5


def make_engine(url: str, **kwargs: Any) -> Engine:
    """Create an engine with sane defaults.

    ``pool_pre_ping`` drops connections that died while idle (database restart) instead of
    failing the next request. The connect timeout keeps a dead database from hanging
    requests and health checks; it is a libpq option, so only set for PostgreSQL.
    """
    if url.startswith("postgresql"):
        connect_args = kwargs.setdefault("connect_args", {})
        connect_args.setdefault("connect_timeout", CONNECT_TIMEOUT_SECONDS)
    kwargs.setdefault("pool_pre_ping", True)
    return create_engine(url, **kwargs)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return make_engine(get_settings().database_url)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    # expire_on_commit=False: objects stay readable after commit, e.g. to render a response.
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def ping_database(engine: Engine) -> None:
    """Raise if the database does not answer a trivial query."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
