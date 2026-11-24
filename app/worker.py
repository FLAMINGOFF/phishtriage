"""RQ worker: the only process that ever parses or analyses a reported email.

Run with ``python -m app.worker``. Jobs are defined in app.jobs and queued by app.queueing.
The worker also runs RQ's scheduler, which re-queues failed jobs after their back-off.
Several workers can run side by side; the VirusTotal rate limit is shared through Redis.
"""

from __future__ import annotations

import logging

from redis import Redis
from rq import Worker

from app.config import get_settings
from app.log import configure_logging
from app.queueing import QUEUE_NAME, SERIALIZER, get_queue
from app.redis_client import get_redis

logger = logging.getLogger(__name__)


def build_worker(connection: Redis) -> Worker:
    return Worker([get_queue(connection)], connection=connection, serializer=SERIALIZER)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    # Build the job context now, so a bad configuration stops the worker at start-up
    # instead of failing every job.
    from app.jobs import get_context

    get_context()
    worker = build_worker(get_redis())
    logger.info("worker %s listening on queue %r", worker.name, QUEUE_NAME)
    # with_scheduler: retries with a back-off are "scheduled" jobs; without a scheduler
    # running somewhere they would never run again.
    worker.work(with_scheduler=True, logging_level=settings.log_level)


if __name__ == "__main__":
    main()
