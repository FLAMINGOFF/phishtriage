"""Container health checks: ``python -m app.healthcheck {web,worker,poller}``.

Docker runs these inside each container (the slim image has no curl). Each process gets
the check that matches what "healthy" means for it:

* web: ``/readyz`` answers 200, i.e. the app is up and can reach PostgreSQL and Redis;
* worker: this container's RQ worker is registered in Redis and its heartbeat is fresh,
  i.e. it is actually consuming the queue rather than merely running;
* poller: it reached the report mailbox recently (heartbeat file).
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from redis import Redis
from rq.worker import BaseWorker, Worker

from app.ingest.imap_poller import HEARTBEAT_FILE, IMAP_TIMEOUT_SECONDS

READYZ_URL = "http://127.0.0.1:8000/readyz"


def check_web(url: str = READYZ_URL, timeout: float = 3.0) -> bool:
    try:
        # Fixed loopback URL, never user input.
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            return bool(response.status == 200)
    except (urllib.error.URLError, OSError):
        return False


def check_worker(
    connection: Redis,
    hostname: str,
    max_age_seconds: float,
    workers: Callable[[Redis], Iterable[BaseWorker]] = lambda conn: Worker.all(connection=conn),
) -> bool:
    now = datetime.now(UTC)
    for worker in workers(connection):
        beat = worker.last_heartbeat
        if worker.hostname != hostname or beat is None:
            continue
        if (now - beat).total_seconds() <= max_age_seconds:
            return True
    return False


def check_poller(
    heartbeat: Path, max_age_seconds: float, now: Callable[[], float] = time.time
) -> bool:
    try:
        age = now() - heartbeat.stat().st_mtime
    except FileNotFoundError:
        return False
    return age <= max_age_seconds


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.healthcheck")
    parser.add_argument("component", choices=["web", "worker", "poller"])
    args = parser.parse_args(argv)

    if args.component == "web":
        healthy = check_web()
    else:
        # Imported here so the web check does not need valid worker/poller settings.
        from app.config import get_settings

        settings = get_settings()
        if args.component == "worker":
            from app.redis_client import get_redis

            # RQ refreshes the heartbeat at least once per worker TTL (420 s by default).
            healthy = check_worker(get_redis(), socket.gethostname(), max_age_seconds=480)
        else:
            # Allow two missed polls (plus a slow IMAP login) before calling it unhealthy.
            max_age = 3 * settings.poll_interval_seconds + IMAP_TIMEOUT_SECONDS
            healthy = check_poller(HEARTBEAT_FILE, max_age)
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
