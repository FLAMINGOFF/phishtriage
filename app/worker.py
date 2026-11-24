"""RQ worker: the only process that ever parses or analyses a reported email.

Run with ``python -m app.worker``. In M0 the worker just consumes the queue; the analysis
pipeline (parse, analyse, intel, score, reply) is added in later milestones.
"""

from __future__ import annotations

import logging

from redis import Redis
from rq import Queue, Worker
from rq.serializers import JSONSerializer

from app.config import get_settings
from app.log import configure_logging
from app.redis_client import get_redis

logger = logging.getLogger(__name__)

QUEUE_NAME = "reports"

# Jobs only ever carry a report ID, so JSON is enough. RQ's default (pickle) would turn
# "someone can write to Redis" into "someone can run code in the worker".
SERIALIZER = JSONSerializer


def get_queue(connection: Redis | None = None) -> Queue:
    return Queue(QUEUE_NAME, connection=connection or get_redis(), serializer=SERIALIZER)


def build_worker(connection: Redis) -> Worker:
    return Worker([get_queue(connection)], connection=connection, serializer=SERIALIZER)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    worker = build_worker(get_redis())
    logger.info("worker %s listening on queue %r", worker.name, QUEUE_NAME)
    worker.work(logging_level=settings.log_level)


if __name__ == "__main__":
    main()
