"""The report queue: how intake channels hand work to the worker.

The web process and the poller only put a report ID on the queue; they never parse or
analyse email themselves. Everything about a job (retries, back-off, timeout, failure
handling) is decided here, in one place.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

from redis import Redis
from redis.exceptions import RedisError
from rq import Callback, Queue, Retry
from rq.serializers import JSONSerializer

from app.redis_client import get_redis

QUEUE_NAME = "reports"

# Jobs only ever carry a report ID, so JSON is enough. RQ's default (pickle) would turn
# "someone can write to Redis" into "someone can run code in the worker".
SERIALIZER = JSONSerializer

JOB_FUNCTION = "app.jobs.process_report"
FAILURE_CALLBACK = "app.jobs.on_report_failure"

# Up to 3 retries with exponential back-off (x3): 10 s, 30 s, 90 s after the failures.
MAX_RETRIES = 3
RETRY_INTERVALS = [10, 30, 90]
# Generous: VirusTotal's free tier alone can make a report wait about a minute.
JOB_TIMEOUT_SECONDS = 600

Enqueue = Callable[[uuid.UUID], None]


class QueueUnavailable(RuntimeError):
    """The report was stored but could not be queued (Redis is unreachable)."""


def job_id(report_id: uuid.UUID) -> str:
    return f"report-{report_id}"


def get_queue(connection: Redis | None = None) -> Queue:
    return Queue(QUEUE_NAME, connection=connection or get_redis(), serializer=SERIALIZER)


def enqueue_report(queue: Queue, report_id: uuid.UUID) -> None:
    try:
        queue.enqueue(
            JOB_FUNCTION,
            str(report_id),
            job_id=job_id(report_id),
            retry=Retry(max=MAX_RETRIES, interval=RETRY_INTERVALS),
            on_failure=Callback(FAILURE_CALLBACK),
            job_timeout=JOB_TIMEOUT_SECONDS,
            result_ttl=24 * 3600,
            failure_ttl=7 * 24 * 3600,
        )
    except RedisError as exc:
        raise QueueUnavailable(str(exc)) from exc


PURGE_FUNCTION = "app.jobs.purge_expired"


def enqueue_purge(connection: Redis) -> None:
    """Queue one run of the retention purge (app.retention)."""
    get_queue(connection).enqueue(
        PURGE_FUNCTION,
        job_timeout=JOB_TIMEOUT_SECONDS,
        result_ttl=7 * 24 * 3600,
        failure_ttl=7 * 24 * 3600,
    )


def rq_enqueuer(connection: Redis) -> Enqueue:
    """The production ``enqueue``: put the report on the RQ queue in Redis."""
    queue = get_queue(connection)

    def enqueue(report_id: uuid.UUID) -> None:
        enqueue_report(queue, report_id)

    return enqueue
