"""Attachment analyzer: what the files are, judged from their bytes and names only."""

from __future__ import annotations

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.parsing.attachments import AttachmentFacts

# Files Windows (or a browser) will run, open as a program, or mount.
EXECUTABLE_EXTENSIONS = frozenset(
    [
        "exe",
        "scr",
        "com",
        "pif",
        "cpl",
        "msi",
        "msp",
        "msix",
        "appx",
        "appxbundle",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vb",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "ws",
        "hta",
        "sct",
        "lnk",
        "url",
        "iso",
        "img",
        "vhd",
        "vhdx",
        "jar",
        "reg",
        "chm",
        "scf",
        "xll",
        "inf",
        "msc",
        "gadget",
        "application",
        "appref-ms",
        "library-ms",
        "settingcontent-ms",
    ]
)
EXECUTABLE_TYPES = frozenset(
    {
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-pie-executable",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/x-ms-shortcut",
        "application/x-iso9660-image",
        "application/java-archive",
        "application/x-msi",
        "application/hta",
        "text/x-msdos-batch",
    }
)
# Extensions attackers put in front of the real one ("invoice.pdf.exe").
DECOY_EXTENSIONS = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "rtf",
        "odt",
        "ods",
        "txt",
        "csv",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "tif",
        "tiff",
        "mp3",
        "mp4",
        "wav",
        "avi",
        "mov",
        "zip",
        "rar",
        "7z",
        "html",
        "htm",
        "eml",
        "msg",
    ]
)
HTML_EXTENSIONS = frozenset({"htm", "html", "xhtml", "xht", "shtml", "svg", "svgz", "mht", "mhtml"})
HTML_TYPES = frozenset({"text/html", "image/svg+xml", "application/xhtml+xml"})
_OLE = (
    "application/msword",
    "application/vnd.ms-",
    "application/x-ole-storage",
    "application/cdfv2",
)
_OOXML = (
    "application/vnd.openxmlformats-",
    "application/vnd.ms-",
    "application/zip",
    "application/x-ole-storage",  # encrypted OOXML is an OLE container
    "application/cdfv2",
    "application/encrypted",
)
# What a file with this extension may really be (prefix match on the detected type).
EXPECTED_TYPES: dict[str, tuple[str, ...]] = {
    "pdf": ("application/pdf",),
    "doc": (*_OLE, "text/rtf", "application/rtf"),
    "dot": _OLE,
    "xls": _OLE,
    "ppt": _OLE,
    **dict.fromkeys(("docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "pptx", "pptm"), _OOXML),
    "rtf": ("text/rtf", "application/rtf"),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "png": ("image/png",),
    "gif": ("image/gif",),
    "bmp": ("image/bmp", "image/x-ms-bmp"),
    "zip": ("application/zip",),
    "txt": ("text/",),
    "csv": ("text/", "application/csv"),
}
UNKNOWN_TYPES = frozenset({"application/octet-stream", "application/x-empty"})
# Bidirectional controls let "photo\u202egpj.exe" display as "photoexe.jpg".
BIDI_CONTROLS = {
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}


def extensions(filename: str) -> list[str]:
    """Lower-case extensions, last one last: "Invoice.PDF.exe" -> ["pdf", "exe"]."""
    parts = filename.strip().rstrip(".").split(".")
    return [p.strip().lower() for p in parts[1:] if p.strip()]


def _is_executable_type(detected: str | None) -> bool:
    return detected is not None and detected.lower() in EXECUTABLE_TYPES


def _mismatch(facts: AttachmentFacts) -> list[str]:
    reasons = []
    bidi = sorted({f"U+{ord(ch):04X}" for ch in facts.filename if ord(ch) in BIDI_CONTROLS})
    if bidi:
        reasons.append(f"file name contains direction control {', '.join(bidi)}")
    exts = extensions(facts.filename)
    if len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS and exts[-1] in EXECUTABLE_EXTENSIONS:
        reasons.append(f"double extension .{exts[-2]}.{exts[-1]}")
    elif "  " in facts.filename and exts and exts[-1] in EXECUTABLE_EXTENSIONS:
        reasons.append("spaces hide the real extension")
    detected = (facts.detected_type or "").lower()
    if exts and detected and detected not in UNKNOWN_TYPES:
        expected = EXPECTED_TYPES.get(exts[-1])
        if (expected is not None and not detected.startswith(expected)) or (
            expected is None
            and _is_executable_type(detected)
            and (exts[-1] not in EXECUTABLE_EXTENSIONS)
        ):
            reasons.append(f".{exts[-1]} file is really {detected}")
    return reasons


def analyze(ctx: AnalysisContext) -> list[Hit]:
    intel_hits: list[Evidence] = []
    executable: list[Evidence] = []
    mismatch: list[Evidence] = []
    macros: list[Evidence] = []
    html: list[Evidence] = []
    encrypted: list[Evidence] = []

    for facts in ctx.attachments:
        name = facts.filename
        exts = extensions(name)
        detected = facts.detected_type or "unknown"
        for result in ctx.intel.hashes.get(facts.sha256, ()):
            if result.is_malicious:
                intel_hits.append(
                    evidence(
                        f"Attachment {name}",
                        facts.sha256,
                        f"{result.provider}: {result.malicious_count} engines flag it malicious",
                    )
                )
        if exts and exts[-1] in EXECUTABLE_EXTENSIONS:
            executable.append(evidence("Attachment", name, f".{exts[-1]} file"))
        elif _is_executable_type(facts.detected_type):
            executable.append(evidence("Attachment", name, f"content is {detected}"))
        for member in facts.members:
            member_exts = extensions(member.name.rsplit("/", 1)[-1])
            if member_exts and member_exts[-1] in EXECUTABLE_EXTENSIONS:
                executable.append(
                    evidence(f"Archive {name}", member.name, f".{member_exts[-1]} file inside")
                )
        mismatch.extend(evidence("Attachment", name, reason) for reason in _mismatch(facts))
        if facts.has_macros:
            macros.append(evidence("Attachment", name, "contains a VBA project"))
        if (exts and exts[-1] in HTML_EXTENSIONS) or detected in HTML_TYPES:
            html.append(evidence("Attachment", name, f"HTML/SVG file ({detected})"))
        if facts.is_encrypted:
            locked = [m.name for m in facts.members if m.encrypted][:5]
            encrypted.append(
                evidence("Attachment", name, f"password-protected: {', '.join(locked)}")
            )

    rules = [
        ("ATT_INTEL_MALICIOUS", intel_hits),
        ("ATT_EXECUTABLE", executable),
        ("ATT_EXT_MISMATCH", mismatch),
        ("ATT_MACRO", macros),
        ("ATT_HTML_FILE", html),
        ("ATT_ENCRYPTED_ARCHIVE", encrypted),
    ]
    return [hit(rule_id, items) for rule_id, items in rules if items]
