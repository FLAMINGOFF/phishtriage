"""Liveness and readiness endpoints."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

Probe = Callable[[], None]
"""A readiness probe returns on success and raises on failure."""

CheckState = Literal["ok", "error"]


class Health(BaseModel):
    status: Literal["ok"]


class Readiness(BaseModel):
    status: CheckState
    checks: dict[str, CheckState]


@router.get("/healthz")
def healthz() -> Health:
    """Liveness: the process is up and serving HTTP.

    Deliberately checks nothing else: a database outage should not make the orchestrator
    restart a web process that is itself fine.
    """
    return Health(status="ok")


@router.get("/readyz", responses={503: {"model": Readiness}})
def readyz(request: Request, response: Response) -> Readiness:
    """Readiness: the web process can reach the database and Redis.

    Failures are logged with details but reported to the client only as ``"error"``:
    an unauthenticated endpoint should not echo hostnames or driver messages.
    """
    probes: Mapping[str, Probe] = request.app.state.probes
    checks: dict[str, CheckState] = {}
    for name, probe in probes.items():
        try:
            probe()
        except Exception:
            logger.warning("readiness probe %r failed", name, exc_info=True)
            checks[name] = "error"
        else:
            checks[name] = "ok"
    ready = all(state == "ok" for state in checks.values())
    if not ready:
        response.status_code = 503
    return Readiness(status="ok" if ready else "error", checks=checks)
