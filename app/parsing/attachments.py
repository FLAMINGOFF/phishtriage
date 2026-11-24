"""Static inspection of attachments: real type, archive listing, VBA macros.

Nothing here executes, extracts or uploads anything:

* archives are *listed* from the ZIP central directory, never decompressed, which rules
  out zip bombs by construction;
* macros are found by ``oletools`` reading the OLE structure, and only after the ZIP
  listing shows that no member is absurdly large.
"""

from __future__ import annotations

import io
import logging
import warnings
import zipfile
from dataclasses import dataclass

from app.parsing.eml import Attachment
from app.parsing.filetype import detect_type

with warnings.catch_warnings():  # oletools still calls pyparsing's deprecated camelCase API
    warnings.simplefilter("ignore", DeprecationWarning)
    from oletools.olevba import VBA_Parser

logger = logging.getLogger(__name__)
logging.getLogger("olevba").setLevel(logging.ERROR)  # oletools is chatty on odd files

MAX_MEMBERS_LISTED = 1000
MAX_MEMBER_BYTES_FOR_MACRO_SCAN = 25 * 1024 * 1024
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    size: int  # declared uncompressed size, as listed; never verified by extracting
    encrypted: bool


@dataclass(frozen=True)
class AttachmentFacts:
    """What inspection found out about one attachment."""

    filename: str
    declared_type: str
    detected_type: str | None
    size: int
    sha256: str
    has_macros: bool | None = None  # None: not an Office file, or could not tell
    is_encrypted: bool | None = None  # None: not an archive we can list
    members: tuple[ArchiveMember, ...] = ()  # only for real archives, not Office files
    members_truncated: bool = False


@dataclass(frozen=True)
class ZipListing:
    members: tuple[ArchiveMember, ...]
    truncated: bool
    is_office: bool  # OOXML (docx, xlsm...) rather than an archive a user opens


def list_zip(data: bytes) -> ZipListing | None:
    """List a ZIP from its central directory; ``None`` if it is not a readable ZIP."""
    if not data.startswith(ZIP_MAGICS):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError):
        return None
    members = tuple(
        ArchiveMember(
            name=info.filename[:255],
            size=info.file_size,
            encrypted=bool(info.flag_bits & 0x1),
        )
        for info in infos[:MAX_MEMBERS_LISTED]
    )
    names = {info.filename for info in infos[:MAX_MEMBERS_LISTED]}
    return ZipListing(
        members=members,
        truncated=len(infos) > MAX_MEMBERS_LISTED,
        is_office="[Content_Types].xml" in names,
    )


def detect_macros(data: bytes, listing: ZipListing | None) -> bool | None:
    """VBA macros in an Office document (OLE or OOXML); ``None`` if not applicable."""
    is_ole = data.startswith(OLE_MAGIC)
    is_ooxml = listing is not None and listing.is_office
    if not (is_ole or is_ooxml):
        return None
    if is_ooxml and listing is not None:
        if any(m.name.lower().endswith("vbaproject.bin") for m in listing.members):
            return True  # where Office stores a VBA project in docm/xlsm/pptm
        if listing.truncated or any(
            m.size > MAX_MEMBER_BYTES_FOR_MACRO_SCAN for m in listing.members
        ):
            return None  # refuse to let oletools read a suspiciously large member
    try:
        parser = VBA_Parser("attachment", data=data)
        try:
            return bool(parser.detect_vba_macros())
        finally:
            parser.close()
    except Exception as exc:  # oletools raises many types on malformed files
        logger.info("macro scan failed: %s", type(exc).__name__)
        return None


def inspect_attachment(attachment: Attachment) -> AttachmentFacts:
    data = attachment.content
    listing = list_zip(data)
    archive = listing is not None and not listing.is_office
    return AttachmentFacts(
        filename=attachment.filename,
        declared_type=attachment.declared_type,
        detected_type=detect_type(data),
        size=attachment.size,
        sha256=attachment.sha256,
        has_macros=detect_macros(data, listing),
        is_encrypted=(any(m.encrypted for m in listing.members) if archive and listing else None),
        members=listing.members if archive and listing else (),
        members_truncated=listing.truncated if archive and listing else False,
    )
