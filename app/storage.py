"""Content-addressed storage for raw messages and attachments.

Files live on a dedicated volume, never in the database (which only keeps the path and
SHA-256). Each file is named by its SHA-256, so:

* an attacker-chosen file name such as ``../../etc/passwd`` never touches the filesystem
  (no path traversal), it is only ever displayed;
* the same attachment reported a hundred times is stored once;
* integrity can be checked by re-hashing.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

BlobKind = Literal["raw", "attachments"]
_RELATIVE = re.compile(r"^(raw|attachments)/[0-9a-f]{2}/[0-9a-f]{64}$")


@dataclass(frozen=True)
class StoredBlob:
    sha256: str
    path: str  # relative to the store root, e.g. "raw/ab/ab12..."
    size: int


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, data: bytes, kind: BlobKind) -> StoredBlob:
        digest = hashlib.sha256(data).hexdigest()
        relative = f"{kind}/{digest[:2]}/{digest}"
        target = self.root / relative
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temporary file and rename: readers never see a half-written file.
            fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                os.chmod(tmp, 0o640)
                os.replace(tmp, target)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        return StoredBlob(sha256=digest, path=relative, size=len(data))

    def resolve(self, relative: str) -> Path:
        """Map a stored relative path back to a file, refusing anything we did not create."""
        if not _RELATIVE.match(relative):
            raise ValueError(f"not a blob path: {relative!r}")
        return self.root / relative

    def read(self, relative: str) -> bytes:
        return self.resolve(relative).read_bytes()

    def delete(self, relative: str) -> bool:
        path = self.resolve(relative)
        existed = path.exists()
        path.unlink(missing_ok=True)
        return existed
