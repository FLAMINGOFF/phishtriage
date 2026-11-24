"""FastAPI dependencies shared by the routers."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Settings
from app.storage import BlobStore


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


def get_store(request: Request) -> BlobStore:
    store: BlobStore = request.app.state.store
    return store


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


async def read_body_limited(request: Request, limit: int) -> bytes:
    """Read the request body, refusing (413) anything over ``limit`` bytes.

    The declared Content-Length is checked first, and the stream is counted as it
    arrives, so a client that lies about (or omits) the length cannot exhaust memory.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"message larger than {limit:,} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"message larger than {limit:,} bytes")
        chunks.append(chunk)
    return b"".join(chunks)
