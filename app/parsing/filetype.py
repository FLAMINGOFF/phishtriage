"""Identify what a file really is from its content (libmagic), never from its name."""

from __future__ import annotations

import logging

import magic

logger = logging.getLogger(__name__)

# libmagic only needs the first bytes; bounding the input bounds the work.
SNIFF_BYTES = 64 * 1024


def detect_type(data: bytes) -> str | None:
    """The MIME type libmagic sees in ``data``; ``None`` when libmagic is unusable.

    ``None`` (unknown) rather than a guess such as ``application/octet-stream``: a broken
    libmagic install must not quietly make every attachment look harmless.
    """
    if not data:
        return "application/x-empty"
    try:
        return str(magic.from_buffer(data[:SNIFF_BYTES], mime=True))
    except magic.MagicException as exc:
        logger.warning("libmagic failed, file type unknown: %s", exc)
        return None
