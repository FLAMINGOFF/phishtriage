"""IMAP poller for the report mailbox.

Run with ``python -m app.ingest.imap_poller``. Every ``POLL_INTERVAL_SECONDS`` it:

1. logs in and makes sure the ``Processed`` and ``Rejected`` folders exist;
2. for each message in the inbox (oldest first, at most 50 per round): reads its size,
   moves anything over the 25 MB limit to ``Rejected`` without downloading it, otherwise
   downloads it (``BODY.PEEK[]``, so it is not marked as read);
3. skips it if a report with the same Message-ID (or, without one, the same SHA-256)
   already exists, else stores it and queues the report for the worker;
4. moves it to ``Processed`` (``UID MOVE``, or ``COPY`` + ``\\Deleted`` + ``EXPUNGE`` on
   servers without MOVE) and writes the heartbeat for the container health check.

Storing before moving means a crash can only lead to the message being seen again, and
the Message-ID check turns that into a no-op instead of a duplicate report.

The poller does not parse emails: it only reads the Message-ID header line. Parsing
attacker-controlled content happens in the worker.
"""

from __future__ import annotations

import hashlib
import imaplib
import logging
import re
import signal
import ssl
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.db.models import Report, ReportSource
from app.ingest.submission import queue_submission
from app.log import configure_logging
from app.parsing.eml import MAX_MESSAGE_BYTES
from app.queueing import Enqueue, QueueUnavailable
from app.storage import BlobStore

logger = logging.getLogger(__name__)

HEARTBEAT_FILE = Path(tempfile.gettempdir()) / "phishtriage-poller.heartbeat"
IMAP_TIMEOUT_SECONDS = 15.0
MAX_MESSAGES_PER_POLL = 50

_SIZE = re.compile(rb"RFC822\.SIZE (\d+)")
_FOLD = re.compile(rb"\r?\n[ \t]+")
_MESSAGE_ID = re.compile(rb"(?im)^message-id:[ \t]*(<[^<>\s]{1,994}>)")


class MailboxError(RuntimeError):
    """The mailbox answered, but not with what we expected."""


def connect(settings: Settings) -> imaplib.IMAP4:
    """Open a connection; TLS with certificate verification when ``IMAP_SSL`` is on."""
    if settings.imap_ssl:
        return imaplib.IMAP4_SSL(
            settings.imap_host,
            settings.imap_port,
            ssl_context=ssl.create_default_context(),
            timeout=IMAP_TIMEOUT_SECONDS,
        )
    return imaplib.IMAP4(settings.imap_host, settings.imap_port, timeout=IMAP_TIMEOUT_SECONDS)


def message_id(raw: bytes) -> str | None:
    """The Message-ID header of a raw message (``<...>`` form only), else ``None``."""
    head = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]
    match = _MESSAGE_ID.search(_FOLD.sub(b" ", head))
    return match.group(1).decode("ascii", "replace") if match else None


def _quote(mailbox: str) -> str:
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ok(response: tuple[str, Sequence[Any]], what: str) -> Sequence[Any]:
    status, data = response
    if status != "OK":
        raise MailboxError(f"{what} failed: {data!r}")
    return data


class Mailbox:
    """The few IMAP operations the poller needs, on top of imaplib, by UID."""

    def __init__(self, conn: imaplib.IMAP4) -> None:
        self.conn = conn
        # Ask again after login: servers may announce more capabilities once logged in.
        data = _ok(conn.capability(), "CAPABILITY")
        first = data[0] if data else b""
        names = first.decode("ascii", "replace").upper().split() if isinstance(first, bytes) else []
        capabilities = set(names) | {c.upper() for c in conn.capabilities}
        self.can_move = "MOVE" in capabilities
        self.has_uidplus = "UIDPLUS" in capabilities

    def ensure_folder(self, name: str) -> None:
        status, _ = self.conn.create(_quote(name))
        if status != "OK":  # usually "already exists"; a real problem shows at MOVE/COPY
            logger.debug("CREATE %s: %s", name, status)

    def open(self, name: str) -> None:
        _ok(self.conn.select(_quote(name)), f"SELECT {name}")

    def uids(self) -> list[str]:
        data = _ok(self.conn.uid("SEARCH", "ALL"), "UID SEARCH")
        first = data[0] if data else b""
        return first.decode("ascii").split() if isinstance(first, bytes) else []

    def size(self, uid: str) -> int:
        data = _ok(self.conn.uid("FETCH", uid, "(RFC822.SIZE)"), "UID FETCH size")
        for item in data:
            text = item[0] if isinstance(item, tuple) else item
            if isinstance(text, bytes) and (match := _SIZE.search(text)):
                return int(match.group(1))
        raise MailboxError(f"no size for message {uid}")

    def fetch(self, uid: str) -> bytes:
        data = _ok(self.conn.uid("FETCH", uid, "(BODY.PEEK[])"), "UID FETCH body")
        for item in data:
            if isinstance(item, tuple) and isinstance(item[1], bytes):
                return item[1]
        raise MailboxError(f"no content for message {uid}")

    def move(self, uid: str, folder: str) -> None:
        if self.can_move:
            _ok(self.conn.uid("MOVE", uid, _quote(folder)), f"UID MOVE to {folder}")
            return
        _ok(self.conn.uid("COPY", uid, _quote(folder)), f"UID COPY to {folder}")
        _ok(self.conn.uid("STORE", uid, "+FLAGS.SILENT", r"(\Deleted)"), "UID STORE")
        if self.has_uidplus:
            _ok(self.conn.uid("EXPUNGE", uid), "UID EXPUNGE")
        else:
            _ok(self.conn.expunge(), "EXPUNGE")


@dataclass
class PollResult:
    queued: int = 0
    duplicates: int = 0
    rejected: int = 0
    report_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Intake:
    """Where messages go: the database, the blob store and the worker queue."""

    sessionmaker: sessionmaker[Session]
    store: BlobStore
    enqueue: Enqueue


def _existing_report(session: Session, raw: bytes, outer_id: str | None) -> Report | None:
    query = select(Report).where(Report.source == ReportSource.IMAP, Report.parent_id.is_(None))
    if outer_id:
        query = query.where(Report.outer_message_id == outer_id)
    else:
        query = query.where(Report.submission_sha256 == hashlib.sha256(raw).hexdigest())
    return session.scalars(query.limit(1)).first()


def take_message(intake: Intake, raw: bytes) -> Report | None:
    """Store and queue one message; ``None`` if it was already taken (a duplicate)."""
    outer_id = message_id(raw)
    with intake.sessionmaker() as session:
        if _existing_report(session, raw, outer_id) is not None:
            return None
        return queue_submission(
            session,
            intake.store,
            intake.enqueue,
            raw,
            source=ReportSource.IMAP,
            outer_message_id=outer_id,
        )


def poll_once(settings: Settings, intake: Intake, heartbeat: Path = HEARTBEAT_FILE) -> PollResult:
    result = PollResult()
    conn = connect(settings)
    try:
        conn.login(settings.imap_user, settings.imap_password.get_secret_value())
        mailbox = Mailbox(conn)
        mailbox.ensure_folder(settings.imap_processed_mailbox)
        mailbox.ensure_folder(settings.imap_rejected_mailbox)
        mailbox.open(settings.imap_mailbox)
        for uid in mailbox.uids()[:MAX_MESSAGES_PER_POLL]:
            if mailbox.size(uid) > MAX_MESSAGE_BYTES:
                logger.warning("message %s is over the size limit: moved to Rejected", uid)
                mailbox.move(uid, settings.imap_rejected_mailbox)
                result.rejected += 1
                continue
            raw = mailbox.fetch(uid)
            try:
                report = take_message(intake, raw)
            except QueueUnavailable:
                # Stored as a failed report; `python -m app.cli requeue --failed` retries.
                # Stop this round: the rest stays in the inbox until Redis is back.
                mailbox.move(uid, settings.imap_processed_mailbox)
                raise
            mailbox.move(uid, settings.imap_processed_mailbox)
            if report is None:
                result.duplicates += 1
            else:
                result.queued += 1
                result.report_ids.append(str(report.id))
    finally:
        try:
            conn.logout()
        except (OSError, imaplib.IMAP4.error):
            logger.debug("logout failed", exc_info=True)
    heartbeat.touch()
    if result.queued or result.duplicates or result.rejected:
        logger.info(
            "mailbox: %d queued, %d duplicate(s), %d rejected",
            result.queued,
            result.duplicates,
            result.rejected,
        )
    return result


def default_intake(settings: Settings) -> Intake:
    from app.db.session import get_sessionmaker
    from app.queueing import rq_enqueuer
    from app.redis_client import redis_client

    return Intake(
        sessionmaker=get_sessionmaker(),
        store=BlobStore(settings.storage_dir),
        enqueue=rq_enqueuer(redis_client(settings.redis_url)),
    )


def run(
    settings: Settings,
    stop: threading.Event,
    heartbeat: Path = HEARTBEAT_FILE,
    intake: Intake | None = None,
    poll: Callable[[Settings, Intake, Path], PollResult] | None = None,
) -> None:
    """Poll until ``stop`` is set.

    Any error is logged and the loop carries on: a poller must survive a mailbox restart.
    A failure that persists shows up as a stale heartbeat, i.e. an unhealthy container.
    """
    intake = intake or default_intake(settings)
    poll = poll or poll_once
    while not stop.is_set():
        try:
            poll(settings, intake, heartbeat)
        except Exception:
            logger.exception("mailbox poll failed")
        stop.wait(settings.poll_interval_seconds)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    stop = threading.Event()

    def _request_stop(signum: int, _frame: FrameType | None) -> None:
        logger.info("received signal %d, stopping", signum)
        stop.set()

    # docker stop sends SIGTERM; finish the current poll instead of dying mid-transfer.
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    logger.info(
        "polling %s:%d every %ds",
        settings.imap_host,
        settings.imap_port,
        settings.poll_interval_seconds,
    )
    run(settings, stop)


if __name__ == "__main__":
    main()
