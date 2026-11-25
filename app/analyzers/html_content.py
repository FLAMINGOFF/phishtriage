"""Bounded, static HTML input shared by link and content analyzers.

Only direct HTML attachments are read. No scripts, archives, links or resources are
executed, expanded or fetched. UTF-8/BOM decoding is deliberately best effort.
"""

from __future__ import annotations

from app.analyzers.base import AnalysisContext
from app.parsing.html import HtmlInfo, analyze_html

MAX_ATTACHMENT_BYTES = 1_000_000
MAX_HTML_ATTACHMENTS = 20
MAX_SCAN_CHARS = 200_000


def html_documents(ctx: AnalysisContext) -> list[tuple[str, HtmlInfo]]:
    documents = []
    if ctx.email.body_html:
        documents.append(("HTML body", analyze_html(ctx.email.body_html[:MAX_SCAN_CHARS])))
    remaining = MAX_ATTACHMENT_BYTES
    count = 0
    for attachment in ctx.email.attachments:
        if not (
            attachment.declared_type in {"text/html", "application/xhtml+xml"}
            or attachment.filename.lower().endswith((".html", ".htm", ".xhtml"))
        ):
            continue
        if count >= MAX_HTML_ATTACHMENTS or remaining <= 0:
            break
        count += 1
        raw = attachment.content[:remaining]
        remaining -= len(raw)
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        text = raw.decode(encoding, errors="replace")[:MAX_SCAN_CHARS]
        documents.append((f"HTML attachment {count}", analyze_html(text)))
    return documents
