"""Parse raw email into a :class:`ParsedEmail`, defensively.

The input is attacker-controlled, so parsing follows three rules:

1. **Bound everything.** Size, number of attachments and MIME nesting depth are limited;
   a message over a limit is rejected with a reason instead of being half-processed.
2. **Never trust declarations.** Charsets may be wrong or unknown, headers malformed,
   encodings broken. Each of those becomes a recorded *defect*, not a crash.
3. **Only read.** Nothing here decompresses, renders, executes or fetches anything.

The *report message* an employee sends is usually only a wrapper. :func:`extract_originals`
finds the suspicious email(s) inside it (``message/rfc822`` attachments), or recognises an
inline forward, where the original headers are lost.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage, Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.parsing.authres import AuthenticationResults, parse_authentication_results
from app.parsing.domains import to_ascii
from app.parsing.html import analyze_html
from app.parsing.received import ReceivedHop, parse_chain

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS = 20
MAX_MIME_DEPTH = 10

MAX_HEADERS_KEPT = 300
MAX_HEADER_CHARS = 8192
MAX_BODY_CHARS = 2_000_000
MAX_FILENAME_CHARS = 255

# Declared charsets that are routinely wrong in the wild, mapped to a superset that
# decodes what senders actually meant. gb2312-labelled mail very often contains GBK.
CHARSET_ALIASES = {
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "x-gbk": "gb18030",
    "cp936": "gb18030",
    "ks_c_5601-1987": "cp949",
    "iso-8859-1": "cp1252",
    "latin1": "cp1252",
    "us-ascii": "utf-8",
    "ascii": "utf-8",
    "unknown-8bit": "utf-8",
    "x-unknown": "utf-8",
    "utf8": "utf-8",
}

_FORWARD_SUBJECT = re.compile(r"^\s*(?:fwd?|fw|wg|tr|rv|转发|轉寄|转寄)\s*[:\uff1a]", re.IGNORECASE)
_FORWARD_MARKERS = re.compile(
    r"-{2,}\s*(?:forwarded message|original message|转发的邮件|原始邮件)\s*-{2,}"
    r"|^begin forwarded message:"
    r"|^-{2,}\s*forwarded by"
    r"|^from:\s.+\n(?:sent|date):\s.+\n(?:to|subject):\s",
    re.IGNORECASE | re.MULTILINE,
)


_ADDRESS = re.compile(r"^[^\s<>()\[\]\\,;:\"@]+@[^\s<>()\[\]\\,;:\"@]+$")
_ADDRESS_IN_TEXT = re.compile(r"[^\s<>()\[\]\\,;:\"@]+@[^\s<>()\[\]\\,;:\"@]+")


@dataclass(frozen=True)
class Limits:
    max_bytes: int = MAX_MESSAGE_BYTES
    max_attachments: int = MAX_ATTACHMENTS
    max_depth: int = MAX_MIME_DEPTH


DEFAULT_LIMITS = Limits()


class MessageRejected(ValueError):
    """The message is over a safety limit or cannot be read as email at all."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Address(BaseModel):
    display_name: str = ""
    address: str
    domain: str = ""


class Attachment(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    declared_type: str
    size: int
    sha256: str
    inline: bool = False
    content: bytes = Field(exclude=True, repr=False)


class ParsedEmail(BaseModel):
    message_id: str | None = None
    subject: str = ""
    from_addr: Address | None = None
    reply_to: list[Address] = Field(default_factory=list)
    to: list[Address] = Field(default_factory=list)
    cc: list[Address] = Field(default_factory=list)
    return_path: str | None = None
    sent_at: datetime | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    received: list[ReceivedHop] = Field(default_factory=list)
    authentication_results: list[AuthenticationResults] = Field(default_factory=list)
    body_text: str = ""
    body_html: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    defects: list[str] = Field(default_factory=list)
    forwarded_inline: bool = False
    size: int
    sha256: str
    raw: bytes = Field(exclude=True, repr=False)


class Intake(BaseModel):
    """What a submitted message turned out to contain."""

    mode: Literal["attachment", "inline", "direct"]
    outer: ParsedEmail
    originals: list[ParsedEmail]


# --------------------------------------------------------------------------- helpers


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def _header(msg: Message, name: str, defects: list[str]) -> str | None:
    """Decoded header value; a malformed header degrades to its raw text."""
    try:
        value = msg.get(name)
    except Exception as exc:  # the header parser can raise on hostile input
        defects.append(f"unreadable {name} header: {type(exc).__name__}")
        raw = next((v for k, v in msg.raw_items() if k.lower() == name.lower()), None)
        return None if raw is None else _clip(" ".join(str(raw).split()), MAX_HEADER_CHARS)
    return None if value is None else _clip(" ".join(str(value).split()), MAX_HEADER_CHARS)


def _all_values(msg: Message, name: str, defects: list[str]) -> list[str]:
    """Every value of a header; hostile values that break the parser degrade to raw text."""
    try:
        return [str(v) for v in msg.get_all(name) or []]
    except Exception as exc:  # the structured header parser can raise on hostile input
        defects.append(f"unreadable {name} header: {type(exc).__name__}")
        return [str(v) for k, v in msg.raw_items() if k.lower() == name.lower()]


def _addresses(msg: Message, name: str, defects: list[str]) -> list[Address]:
    values = _all_values(msg, name, defects)
    result: list[Address] = []
    try:
        pairs = getaddresses(values)
    except Exception as exc:
        defects.append(f"unreadable {name} addresses: {type(exc).__name__}")
        return result
    for display, address in pairs:
        address = address.strip().strip("<>")
        if not _ADDRESS.match(address):
            # Malformed header ("Unclosed Quote <a@b.example"): salvage an embedded address.
            embedded = _ADDRESS_IN_TEXT.search(f"{display} {address}")
            if address or display:
                defects.append(f"malformed {name} address: {_clip(address or display, 80)!r}")
            if embedded is None:
                continue
            address = embedded.group(0)
            display = display if display and "@" not in display else ""
        local, _, domain = address.rpartition("@")
        domain = to_ascii(domain)
        result.append(
            Address(
                display_name=_clip(" ".join(display.split()), 500),
                address=f"{local}@{domain}",
                domain=domain,
            )
        )
    return result


def _date(msg: Message, defects: list[str]) -> datetime | None:
    raw = _header(msg, "Date", defects)
    if not raw:
        return None
    try:
        value = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        defects.append(f"invalid Date header: {_clip(raw, 80)!r}")
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def decode_text_part(part: Message, defects: list[str]) -> str:
    """Decode a text part, surviving wrong or unknown charsets."""
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    declared = (part.get_content_charset() or "utf-8").lower()
    charset = CHARSET_ALIASES.get(declared, declared)
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):  # unknown name, NUL in the name, or a bad codec
        defects.append(f"unknown charset {_clip(declared, 40)!r}, decoded as UTF-8")
        return payload.decode("utf-8", errors="replace")


def _filename(part: Message, index: int, defects: list[str]) -> str | None:
    try:
        name = part.get_filename()
    except Exception as exc:
        defects.append(f"unreadable attachment filename: {type(exc).__name__}")
        name = None
    if name is None:
        return None
    # Keep the name exactly as sent (an RTLO character is evidence), but bound it and
    # drop NUL and line breaks, which have no business in a file name.
    name = "".join(ch for ch in name if ch not in "\x00\r\n")
    return _clip(name, MAX_FILENAME_CHARS) or f"attachment-{index}"


# Re-serialising an embedded message must reproduce it, not "fix" it: headers are written
# back as they arrived (no refolding, no header checks) and 8-bit bodies stay 8-bit.
_PASSTHROUGH = policy.default.clone(
    linesep="\r\n", refold_source="none", cte_type="8bit", verify_generated_headers=False
)


def _embedded_bytes(part: Message, defects: list[str]) -> bytes:
    """Raw bytes of a ``message/rfc822`` part (some clients wrongly base64 it)."""
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        inner = payload[0]
        if isinstance(inner, Message):
            for serialise_policy in (_PASSTHROUGH, policy.compat32.clone(linesep="\r\n")):
                try:
                    return inner.as_bytes(policy=serialise_policy)
                except Exception as exc:  # hostile headers or bodies the generator rejects
                    failure = type(exc).__name__
            defects.append(f"embedded message could not be re-read: {failure}")
            return b""
    decoded = part.get_payload(decode=True)
    return decoded if isinstance(decoded, bytes) else b""


@dataclass
class _Walk:
    leaves: list[tuple[Message, int]]
    embedded: list[Message]


def _walk(msg: Message, limits: Limits, depth_offset: int) -> _Walk:
    walk = _Walk(leaves=[], embedded=[])
    stack: list[tuple[Message, int]] = [(msg, depth_offset)]
    while stack:
        part, depth = stack.pop()
        if depth > limits.max_depth:
            raise MessageRejected(f"MIME nesting deeper than {limits.max_depth} levels")
        ctype = part.get_content_type()
        if ctype in ("message/rfc822", "message/global") and part is not msg:
            walk.embedded.append(part)
            continue
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                # Reverse so that parts come off the stack in document order.
                stack.extend(
                    (sub, depth + 1) for sub in reversed(payload) if isinstance(sub, Message)
                )
            continue
        walk.leaves.append((part, depth))
    return walk


# --------------------------------------------------------------------------- public API


def parse_message(
    raw: bytes, limits: Limits = DEFAULT_LIMITS, *, depth_offset: int = 0
) -> tuple[ParsedEmail, list[bytes]]:
    """Parse one message. Returns it and the raw bytes of any embedded messages.

    Embedded ``message/rfc822`` parts are not descended into here; the caller decides
    whether they are the reported originals (wrapper) or attachments (an email that
    itself attaches an email).
    """
    if len(raw) > limits.max_bytes:
        raise MessageRejected(
            f"message is {len(raw):,} bytes, the limit is {limits.max_bytes:,} bytes"
        )
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception as exc:  # pragma: no cover - the feed parser is very forgiving
        raise MessageRejected(f"not a readable email message: {type(exc).__name__}") from exc
    if not isinstance(msg, EmailMessage) or not msg.keys():
        raise MessageRejected("not an email message: no headers found")

    defects = [type(d).__name__ for d in msg.defects]
    walk = _walk(msg, limits, depth_offset)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    embedded_raw: list[bytes] = []
    for index, (part, _depth) in enumerate(walk.leaves):
        defects.extend(type(d).__name__ for d in part.defects)
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = _filename(part, index, defects)
        if disposition != "attachment" and filename is None and ctype == "text/plain":
            text_parts.append(decode_text_part(part, defects))
            continue
        if disposition != "attachment" and filename is None and ctype == "text/html":
            html_parts.append(decode_text_part(part, defects))
            continue
        content = part.get_payload(decode=True)
        if not isinstance(content, bytes):
            content = b""
        name = filename or f"part-{index}.bin"
        if name.lower().endswith(".eml") and ctype in ("application/octet-stream", "text/plain"):
            # Outlook and webmail sometimes attach the original as "foo.eml" octet-stream.
            embedded_raw.append(content)
        attachments.append(
            Attachment(
                filename=name,
                declared_type=ctype,
                size=len(content),
                sha256=_sha256(content),
                inline=disposition == "inline",
                content=content,
            )
        )
    for part in walk.embedded:
        content = _embedded_bytes(part, defects)
        embedded_raw.append(content)
        attachments.append(
            Attachment(
                filename=_filename(part, len(attachments), defects) or "attached-message.eml",
                declared_type=part.get_content_type(),
                size=len(content),
                sha256=_sha256(content),
                content=content,
            )
        )
    if len(attachments) > limits.max_attachments:
        raise MessageRejected(
            f"{len(attachments)} attachments, the limit is {limits.max_attachments}"
        )

    body_text = "\n".join(t.strip("\r\n") for t in text_parts if t.strip())
    body_html = "\n".join(html_parts) if html_parts else None
    if not body_text and body_html:
        body_text = analyze_html(body_html).text  # HTML-only mail: analyse its text
    if len(body_text) > MAX_BODY_CHARS:
        defects.append(f"body text truncated to {MAX_BODY_CHARS:,} characters")
        body_text = body_text[:MAX_BODY_CHARS]
    if body_html is not None and len(body_html) > MAX_BODY_CHARS:
        defects.append(f"HTML body truncated to {MAX_BODY_CHARS:,} characters")
        body_html = body_html[:MAX_BODY_CHARS]

    headers: list[tuple[str, str]] = []
    for name, value in msg.raw_items():
        if len(headers) >= MAX_HEADERS_KEPT:
            defects.append(f"more than {MAX_HEADERS_KEPT} headers, the rest not kept")
            break
        headers.append((name, _clip(" ".join(str(value).split()), MAX_HEADER_CHARS)))

    auth_results = []
    for value in _all_values(msg, "Authentication-Results", defects):
        parsed = parse_authentication_results(value)
        if parsed is not None:
            auth_results.append(parsed)

    from_list = _addresses(msg, "From", defects)
    return_path = _header(msg, "Return-Path", defects)
    message_id = _header(msg, "Message-ID", defects)
    parsed_email = ParsedEmail(
        message_id=message_id.strip() if message_id else None,
        subject=_header(msg, "Subject", defects) or "",
        from_addr=from_list[0] if from_list else None,
        reply_to=_addresses(msg, "Reply-To", defects),
        to=_addresses(msg, "To", defects),
        cc=_addresses(msg, "Cc", defects),
        return_path=return_path.strip().strip("<>") or None if return_path else None,
        sent_at=_date(msg, defects),
        headers=headers,
        received=parse_chain(_all_values(msg, "Received", defects)),
        authentication_results=auth_results,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        defects=list(dict.fromkeys(defects)),
        size=len(raw),
        sha256=_sha256(raw),
        raw=raw,
    )
    return parsed_email, embedded_raw


def looks_forwarded_inline(parsed: ParsedEmail) -> bool:
    """Heuristic for "the reporter pressed Forward instead of Forward as attachment"."""
    return bool(_FORWARD_SUBJECT.match(parsed.subject) or _FORWARD_MARKERS.search(parsed.body_text))


def extract_originals(
    raw: bytes, *, is_report_wrapper: bool, limits: Limits = DEFAULT_LIMITS
) -> Intake:
    """Find the email(s) to analyse in a submitted message.

    * ``attachment``: the submission carries the original(s) as ``message/rfc822`` (or
      ``.eml``) attachments. Each becomes its own report.
    * ``inline``: the reporter forwarded inline, so the original headers are gone; the
      submission itself is analysed with ``forwarded_inline`` set (body and links only).
    * ``direct``: an analyst uploaded the suspicious email itself.

    ``is_report_wrapper`` is true for the report mailbox, where every message comes from
    a reporter, never directly from the attacker.
    """
    outer, embedded = parse_message(raw, limits)
    embedded = [data for data in embedded if data.strip()]  # unreadable ones are left out
    if embedded:
        originals = [parse_message(data, limits, depth_offset=1)[0] for data in embedded]
        return Intake(mode="attachment", outer=outer, originals=originals)
    if is_report_wrapper or looks_forwarded_inline(outer):
        inline = outer.model_copy(update={"forwarded_inline": True})
        return Intake(mode="inline", outer=outer, originals=[inline])
    return Intake(mode="direct", outer=outer, originals=[outer])
