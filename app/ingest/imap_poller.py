"""IMAP poller for the report mailbox.

Run with ``python -m app.ingest.imap_poller``. M0 proves the plumbing only: every
``POLL_INTERVAL_SECONDS`` it logs in, counts the waiting messages and writes a heartbeat
for the container health check. Fetching, de-duplication and queueing arrive in M5.
"""

from __future__ import annotations

import imaplib
import logging
import signal
import ssl
import tempfile
import threading
from pathlib import Path
from types import FrameType

from app.config import Settings, get_settings
from app.log import configure_logging

logger = logging.getLogger(__name__)

HEARTBEAT_FILE = Path(tempfile.gettempdir()) / "phishtriage-poller.heartbeat"
IMAP_TIMEOUT_SECONDS = 15.0


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


def count_waiting(settings: Settings) -> int:
    """Log in and return how many messages wait in the report mailbox."""
    conn = connect(settings)
    try:
        conn.login(settings.imap_user, settings.imap_password.get_secret_value())
        # EXAMINE (read-only SELECT) so that merely looking never marks messages as read.
        status, data = conn.select(settings.imap_mailbox, readonly=True)
        if status != "OK" or not data or not isinstance(data[0], bytes):
            raise MailboxError(f"cannot open mailbox {settings.imap_mailbox!r}")
        return int(data[0])
    finally:
        try:
            conn.logout()
        except (OSError, imaplib.IMAP4.error):
            logger.debug("logout failed", exc_info=True)


def write_heartbeat(path: Path) -> None:
    path.touch()


def poll_once(settings: Settings, heartbeat: Path = HEARTBEAT_FILE) -> int:
    waiting = count_waiting(settings)
    write_heartbeat(heartbeat)
    logger.info("report mailbox reachable, %d message(s) waiting", waiting)
    return waiting


def run(settings: Settings, stop: threading.Event, heartbeat: Path = HEARTBEAT_FILE) -> None:
    """Poll until ``stop`` is set.

    Any error is logged and the loop carries on: a poller must survive a mailbox restart.
    A failure that persists shows up as a stale heartbeat, i.e. an unhealthy container.
    """
    while not stop.is_set():
        try:
            poll_once(settings, heartbeat)
        except Exception:
            logger.exception("mailbox check failed")
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
