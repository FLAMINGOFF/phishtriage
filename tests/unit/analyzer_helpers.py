"""Build small emails and run one analyzer on them."""

from __future__ import annotations

from datetime import datetime
from email.message import EmailMessage

from app.analyzers.base import AnalysisContext, Analyzer, Hit
from app.config import Policy
from app.intel.models import EMPTY_SNAPSHOT, IntelSnapshot
from app.parsing.attachments import inspect_attachment
from app.parsing.eml import parse_message

TRUSTED = "mx.example.edu"


def message(
    *,
    from_: str = "Sender <sender@sender.example>",
    subject: str = "Hello",
    text: str = "Hello there.",
    html: str | None = None,
    auth: list[str] | None = None,
    reply_to: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> bytes:
    msg = EmailMessage()
    for value in auth or []:
        msg["Authentication-Results"] = value
    msg["From"] = from_
    msg["To"] = "alice@example.edu"
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, ctype, data in attachments or []:
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return bytes(msg)


def run(
    analyzer: Analyzer,
    raw: bytes,
    policy: Policy,
    *,
    intel: IntelSnapshot = EMPTY_SNAPSHOT,
    now: datetime | None = None,
    inline: bool = False,
) -> dict[str, Hit]:
    parsed, _ = parse_message(raw)
    if inline:
        parsed = parsed.model_copy(update={"forwarded_inline": True})
    ctx = AnalysisContext(
        email=parsed,
        policy=policy,
        attachments=tuple(inspect_attachment(a) for a in parsed.attachments),
        intel=intel,
        now=now,
    )
    hits = analyzer(ctx)
    assert len({h.rule_id for h in hits}) == len(hits), "a rule fired twice"
    for item in hits:
        assert item.evidence, f"{item.rule_id} without evidence"
    return {h.rule_id: h for h in hits}
