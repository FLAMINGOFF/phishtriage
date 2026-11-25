"""Attachment inspection and rules: each rule triggers and does not trigger."""

from __future__ import annotations

import base64
import struct

import pytest

from app.analyzers import attachments
from app.analyzers.attachments import extensions
from app.config import Policy
from app.intel.models import IntelResult, IntelSnapshot
from app.parsing.attachments import detect_macros, list_zip
from app.parsing.eml import Attachment
from scripts.generate_emails import (
    FAKE_LNK,
    FAKE_PDF,
    FAKE_PE,
    VBA_PROJECT_BIN,
    ole_file,
    zip_bytes,
)
from tests.unit.analyzer_helpers import message, run

RTLO = chr(0x202E)
# A complete 1x1 PNG: a signature followed by zeroes is not a valid image and newer
# libmagic versions correctly reject it, making the benign-file test platform-dependent.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/"
    "ScLbtAAAAABJRU5ErkJggg=="
)
OOXML = {"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}


def attach(*files: tuple[str, str, bytes]) -> bytes:
    return message(text="See attached.", attachments=list(files))


def rules_for(policy: Policy, *files: tuple[str, str, bytes], intel=None) -> set[str]:
    kwargs = {"intel": intel} if intel is not None else {}
    return set(run(attachments.analyze, attach(*files), policy, **kwargs))


def test_extensions() -> None:
    assert extensions("Invoice.PDF.exe") == ["pdf", "exe"]
    assert extensions("report") == []
    assert extensions("archive.tar.gz") == ["tar", "gz"]
    assert extensions("trailing.dot.") == ["dot"]


def test_intel_malicious(example_policy: Policy) -> None:
    from hashlib import sha256

    digest = sha256(FAKE_PDF).hexdigest()
    bad = IntelSnapshot(
        hashes={digest: (IntelResult(provider="virustotal", status="hit", malicious_count=7),)}
    )
    assert "ATT_INTEL_MALICIOUS" in rules_for(
        example_policy, ("a.pdf", "application/pdf", FAKE_PDF), intel=bad
    )
    meh = IntelSnapshot(
        hashes={digest: (IntelResult(provider="virustotal", status="hit", malicious_count=1),)}
    )
    assert "ATT_INTEL_MALICIOUS" not in rules_for(
        example_policy, ("a.pdf", "application/pdf", FAKE_PDF), intel=meh
    )


@pytest.mark.parametrize(
    "file",
    [
        ("setup.exe", "application/octet-stream", FAKE_PE),
        ("Scan.lnk", "application/octet-stream", FAKE_LNK),
        ("invoice.js", "text/javascript", b"var x = 1;"),
        ("disk.iso", "application/octet-stream", b"\x00" * 64),
        ("statement.pdf", "application/pdf", FAKE_PE),  # content gives it away
        ("files.zip", "application/zip", zip_bytes({"docs/payload.vbs": b"x"})),  # inside
    ],
)
def test_executable(example_policy: Policy, file: tuple[str, str, bytes]) -> None:
    assert "ATT_EXECUTABLE" in rules_for(example_policy, file)


def test_not_executable(example_policy: Policy) -> None:
    found = rules_for(
        example_policy,
        ("report.pdf", "application/pdf", FAKE_PDF),
        ("photo.png", "image/png", PNG),
        ("files.zip", "application/zip", zip_bytes({"a.pdf": FAKE_PDF, "b.txt": b"hi"})),
    )
    assert found == set()


@pytest.mark.parametrize(
    "file",
    [
        ("invoice.pdf.exe", "application/octet-stream", FAKE_PE),
        (f"photo{RTLO}gpj.exe", "application/octet-stream", FAKE_PE),
        ("statement.pdf", "application/pdf", FAKE_PE),
        ("photo.jpg", "image/jpeg", FAKE_PDF),  # a PDF named .jpg
        ("invoice.pdf          .exe", "application/octet-stream", FAKE_PE),
    ],
)
def test_ext_mismatch(example_policy: Policy, file: tuple[str, str, bytes]) -> None:
    assert "ATT_EXT_MISMATCH" in rules_for(example_policy, file)


@pytest.mark.parametrize(
    "file",
    [
        ("report.pdf", "application/pdf", FAKE_PDF),
        ("photo.png", "image/png", PNG),
        ("notes.txt", "text/plain", b"plain notes"),
        ("letter.docx", "application/vnd.openxmlformats", zip_bytes(OOXML)),
        ("backup.tar.gz", "application/gzip", b"\x1f\x8b\x08\x00" + b"\x00" * 20),
        ("unknown.pdf", "application/pdf", b"\x00\x01\x02\x03 random"),  # type unknown
        ("setup.exe", "application/octet-stream", FAKE_PE),  # honest name
    ],
)
def test_no_ext_mismatch(example_policy: Policy, file: tuple[str, str, bytes]) -> None:
    assert "ATT_EXT_MISMATCH" not in rules_for(example_policy, file)


def test_macros(example_policy: Policy) -> None:
    docm = zip_bytes({**OOXML, "word/vbaProject.bin": VBA_PROJECT_BIN})
    assert "ATT_MACRO" in rules_for(example_policy, ("r.docm", "application/zip", docm))
    assert "ATT_MACRO" in rules_for(
        example_policy, ("old.doc", "application/msword", VBA_PROJECT_BIN)
    )
    plain_ole = ole_file({}, {"WordDocument": b"text"})
    assert "ATT_MACRO" not in rules_for(
        example_policy, ("old.doc", "application/msword", plain_ole)
    )
    assert "ATT_MACRO" not in rules_for(
        example_policy, ("r.docx", "application/zip", zip_bytes(OOXML))
    )


def test_macro_scan_guards() -> None:
    assert detect_macros(FAKE_PDF, None) is None  # not an Office file
    # A member that claims to be huge is never handed to oletools.
    bomb = bytearray(zip_bytes({**OOXML, "word/embeddings/oleObject1.bin": b"x"}))
    central = bomb.rfind(b"PK\x01\x02")
    struct.pack_into("<I", bomb, central + 24, 2**31)  # uncompressed size in the listing
    listing = list_zip(bytes(bomb))
    assert listing is not None
    assert detect_macros(bytes(bomb), listing) is None
    assert detect_macros(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 broken", None) is None


def test_html_file(example_policy: Policy) -> None:
    page = b"<html><body><script>location='x'</script></body></html>"
    assert "ATT_HTML_FILE" in rules_for(example_policy, ("advice.html", "text/html", page))
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'
    assert "ATT_HTML_FILE" in rules_for(example_policy, ("logo.svg", "image/svg+xml", svg))
    assert "ATT_HTML_FILE" not in rules_for(example_policy, ("a.pdf", "application/pdf", FAKE_PDF))


def test_encrypted_archive(example_policy: Policy) -> None:
    locked = zip_bytes({"scan.pdf": FAKE_PDF}, encrypt_flag=True)
    hits = run(attachments.analyze, attach(("docs.zip", "application/zip", locked)), example_policy)
    assert "ATT_ENCRYPTED_ARCHIVE" in hits
    assert "scan.pdf" in hits["ATT_ENCRYPTED_ARCHIVE"].evidence[0].match
    open_zip = zip_bytes({"scan.pdf": FAKE_PDF})
    assert "ATT_ENCRYPTED_ARCHIVE" not in rules_for(
        example_policy, ("d.zip", "application/zip", open_zip)
    )


def test_zip_listing_never_extracts() -> None:
    assert list_zip(b"not a zip") is None
    assert list_zip(b"PK\x03\x04 truncated garbage") is None
    many = zip_bytes({f"f{i}.txt": b"" for i in range(1005)})
    listing = list_zip(many)
    assert listing is not None
    assert listing.truncated
    assert len(listing.members) == 1000


def test_inspection_of_an_attachment() -> None:
    from app.parsing.attachments import inspect_attachment

    locked = zip_bytes({"a.exe": FAKE_PE}, encrypt_flag=True)
    facts = inspect_attachment(
        Attachment(
            filename="a.zip",
            declared_type="application/zip",
            size=len(locked),
            sha256="0" * 64,
            content=locked,
        )
    )
    assert facts.detected_type == "application/zip"
    assert facts.is_encrypted is True
    assert facts.has_macros is None
    assert [m.name for m in facts.members] == ["a.exe"]
