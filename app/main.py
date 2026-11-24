"""FastAPI application factory.

Run with ``uvicorn app.main:create_app --factory``. A factory (instead of a module-level
``app``) means importing this module has no side effects: tests build their own app with
their own settings, database and fake probes.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.config import Settings, get_settings
from app.db.session import get_engine, get_sessionmaker, ping_database
from app.ingest import api, upload
from app.log import configure_logging
from app.parsing.eml import MAX_MESSAGE_BYTES
from app.queueing import Enqueue, rq_enqueuer
from app.redis_client import ping_redis, redis_client
from app.storage import BlobStore
from app.web.routes import health, reports
from app.web.routes.health import Probe
from app.web.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware

STATIC_DIR = Path(__file__).parent / "web" / "static"
# Room for multipart framing around a maximum-size message.
MAX_REQUEST_BYTES = MAX_MESSAGE_BYTES + 256 * 1024


def default_probes(settings: Settings) -> dict[str, Probe]:
    return {
        "database": lambda: ping_database(get_engine()),
        "redis": lambda: ping_redis(settings.redis_url),
    }


def create_app(
    settings: Settings | None = None,
    probes: Mapping[str, Probe] | None = None,
    session_factory: sessionmaker[Session] | None = None,
    store: BlobStore | None = None,
    enqueue: Enqueue | None = None,
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
    app.state.sessionmaker = session_factory or get_sessionmaker()
    app.state.store = store or BlobStore(settings.storage_dir)
    # How submissions reach the worker; tests pass a synchronous stand-in.
    app.state.enqueue = enqueue or rq_enqueuer(redis_client(settings.redis_url))

    # Order: the size limit wraps everything, so oversized bodies never reach a handler.
    app.add_middleware(
        SecurityHeadersMiddleware, exempt_prefixes=("/docs", "/openapi.json") if dev else ()
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)

    app.include_router(health.router)
    app.include_router(api.router)
    app.include_router(upload.router)
    app.include_router(reports.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
