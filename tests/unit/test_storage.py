"""Content-addressed blob store."""

from __future__ import annotations

import hashlib
import stat

import pytest

from app.storage import BlobStore


def test_put_read_delete(store: BlobStore) -> None:
    data = b"From: a@example.com\r\n\r\nhi"
    digest = hashlib.sha256(data).hexdigest()
    blob = store.put(data, "raw")
    assert blob.sha256 == digest
    assert blob.path == f"raw/{digest[:2]}/{digest}"
    assert blob.size == len(data)
    assert store.read(blob.path) == data
    assert stat.S_IMODE(store.resolve(blob.path).stat().st_mode) == 0o640
    assert store.put(data, "raw") == blob  # idempotent
    assert store.delete(blob.path) is True
    assert store.delete(blob.path) is False


def test_no_temporary_files_left(store: BlobStore) -> None:
    blob = store.put(b"x", "attachments")
    siblings = list(store.resolve(blob.path).parent.iterdir())
    assert [p.name for p in siblings] == [blob.sha256]


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "raw/../../x",
        "/etc/passwd",
        "raw/ab/" + "g" * 64,
        "other/ab/" + "a" * 64,
        "raw/ab/" + "a" * 63,
        "raw/ab/" + "a" * 64 + "/..",
    ],
)
def test_resolve_refuses_foreign_paths(store: BlobStore, path: str) -> None:
    with pytest.raises(ValueError, match="not a blob path"):
        store.resolve(path)


def test_detect_type() -> None:
    from app.parsing.filetype import detect_type

    assert detect_type(b"") == "application/x-empty"
    assert detect_type(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n") == "application/pdf"
    assert detect_type(b"PK\x05\x06" + b"\x00" * 18) == "application/zip"


def test_detect_type_when_libmagic_is_broken(monkeypatch: pytest.MonkeyPatch) -> None:
    import magic

    from app.parsing import filetype

    def broken(*_args: object, **_kwargs: object) -> str:
        raise magic.MagicException(b"could not find any valid magic files!")

    monkeypatch.setattr(filetype.magic, "from_buffer", broken)
    assert filetype.detect_type(b"MZ") is None
