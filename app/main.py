"""FastAPI application factory.

Run with ``uvicorn app.main:create_app --factory``. A factory (instead of a module-level
``app``) means importing this module has no side effects: tests build their own app with
their own settings and fake probes.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import FastAPI

from app import __version__
from app.config import Settings, get_settings
from app.db.session import get_engine, ping_database
from app.log import configure_logging
from app.redis_client import ping_redis
from app.web.routes import health
from app.web.routes.health import Probe


def default_probes(settings: Settings) -> dict[str, Probe]:
    return {
        "database": lambda: ping_database(get_engine()),
        "redis": lambda: ping_redis(settings.redis_url),
    }


def create_app(
    settings: Settings | None = None, probes: Mapping[str, Probe] | None = None
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    # Interactive API docs only in development: in production they advertise the attack
    # surface and pull Swagger UI from a CDN.
    dev = settings.app_env == "dev"
    app = FastAPI(
        title="PhishTriage",
        version=__version__,
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )
    app.state.settings = settings
    app.state.probes = dict(probes) if probes is not None else default_probes(settings)
    app.include_router(health.router)
    return app
