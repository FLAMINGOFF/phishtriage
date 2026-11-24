"""Logging setup shared by the web, worker and poller processes."""

from __future__ import annotations

import logging

LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def configure_logging(level: str = "INFO") -> None:
    """Send logs to stderr, where Docker collects them.

    ``force=True`` replaces handlers that libraries (or an earlier call) installed, so each
    process gets exactly one handler and no duplicated lines.
    """
    logging.basicConfig(level=level, format=LOG_FORMAT, force=True)
