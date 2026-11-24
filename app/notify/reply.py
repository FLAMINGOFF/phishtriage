"""Reply to the person who reported an email to the report mailbox.

Anti-abuse rules (the plan's "reply abuse" section), checked in this order:

* only reports that arrived in the report mailbox get a reply, once, from the first
  report of a submission (one reply covers every email it carried);
* the reporter's address is in one of ``policy.org_domains``;
* our own mail server vouches for the reporter: the topmost *trusted*
  ``Authentication-Results`` header of the report says ``dmarc=pass`` for the reporter's
  domain. Without this anyone could make PhishTriage mail an arbitrary internal address
  (a spam reflector), because the From address of an email is just text;
* at most ``REPLY_HOURLY_LIMIT`` (20) replies per reporter and hour.

Whatever is decided is stored in ``reports.reply_status`` and shown in the console.

The reply is plain text built from our own wording: the verdict, advice for that verdict,
and the descriptions of the rules that matched. The only text taken from the reported
email is its subject, cleaned and defanged so that a mail client cannot turn it into a
link. Replies never call an email "safe" (plan: "no issues found" at most).
"""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Policy, Settings
from app.db.models import Report, ReportSource, ReportStatus, Verdict, utcnow
from app.parsing.eml import ParsedEmail
from app.scoring.engine import RULES_FILE, VERDICT_LABELS, cached_rules

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"
SMTP_TIMEOUT_SECONDS = 15.0
MAX_REASONS = 5
MAX_SUBJECT_CHARS = 100

SENT = "sent"
ADVICE = {
    Verdict.MALICIOUS: (
        "This is a phishing email. Please delete it. Do not click its links, open its "
        "attachments or reply to it. If you already clicked a link, entered your password "
        "or opened an attachment, contact the IT Service Desk immediately."
    ),
    Verdict.SUSPICIOUS: (
        "This email is very likely phishing. Please do not click its links, open its "
        "attachments or reply to it. A security analyst will review it."
    ),
    Verdict.LOW_RISK: (
        "This email looks like marketing or spam rather than a targeted attack. You can "
        "delete it. Do not enter your password through its links."
    ),
    Verdict.NO_ISSUES: (
        "Our automatic checks found no issues. That does not prove the email is genuine: "
        "if anything about it still seems wrong, do not click its links and contact the "
        "IT Service Desk."
    ),
}
INLINE_HINT = (
    "Tip: next time, please forward suspicious emails as an attachment (in most mail "
    'programs: "More" > "Forward as attachment"). An inline forward loses the original '
    "headers, so we could only check the text and the links."
)
_VERDICT_ORDER = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.LOW_RISK, Verdict.NO_ISSUES]
_MESSAGE_ID = re.compile(r"^<[^<>\s]{1,994}>$")
_DOMAIN_LIKE = re.compile(r"[\w-]+(?:\.[\w-]+)+", re.UNICODE)
_SCHEME = re.compile(r"\b(h)(tt)(ps?)(?=:)", re.IGNORECASE)

_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=False,  # noqa: S701 - plain-text email, no HTML anywhere
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


# --------------------------------------------------------------------------- reporter checks


def reporter_dmarc(outer: ParsedEmail, policy: Policy) -> str | None:
    """DMARC result for the reporter's own address, as our mail server recorded it.

    Only the topmost ``Authentication-Results`` header with a trusted authserv-id counts
    (added last, by our server). Our MX must remove such headers from incoming mail
    (RFC 8601, section 5), so a sender cannot plant one. ``None``: no trusted header, or
    no DMARC result in it.
    """
    if outer.from_addr is None:
        return None
    trusted = set(policy.trusted_authserv_ids)
    header = next(
        (h for h in outer.authentication_results if h.authserv_id.lower() in trusted), None
    )
    if header is None:
        return None
    domain = outer.from_addr.domain.lower()
    for result in header.results:
        if result.method != "dmarc":
            continue
        checked = result.properties.get("header.from", "").lower()
        if checked and checked != domain:
            continue  # a result about another domain says nothing about this reporter
        return result.result[:16]
    return None


def is_org_address(address: str, policy: Policy) -> bool:
    domain = address.rpartition("@")[2].lower()
    return any(domain == own or domain.endswith("." + own) for own in policy.org_domains)


@dataclass(frozen=True)
class Decision:
    send: bool
    status: str | None  # stored in reports.reply_status; None: nothing to record


def decide(session: Session, report: Report, settings: Settings) -> Decision:
    if report.source is not ReportSource.IMAP or report.parent_id is not None:
        return Decision(False, None)  # uploads and API calls have no one to answer
    if report.replied_at is not None:
        return Decision(False, report.reply_status)  # re-analysis: never a second reply
    if not settings.replies_enabled:
        return Decision(False, "not sent: replies are disabled")
    reporter = report.reporter_email
    if not reporter:
        return Decision(False, "not sent: no reporter address")
    if not is_org_address(reporter, settings.policy):
        return Decision(False, "not sent: reporter outside the organisation")
    if report.reporter_dmarc != "pass":
        return Decision(False, "not sent: reporter address not confirmed by DMARC")
    recent = session.scalar(
        select(func.count())
        .select_from(Report)
        .where(
            Report.reporter_email == reporter,
            Report.replied_at >= utcnow() - timedelta(hours=1),
        )
    )
    if (recent or 0) >= settings.reply_hourly_limit:
        return Decision(False, "not sent: hourly reply limit reached")
    return Decision(True, None)


# --------------------------------------------------------------------------- the message


def clean_subject(subject: str | None) -> str:
    """The reported subject, made harmless for a plain-text email and its Subject line."""
    text = "".join(
        " " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else ch
        for ch in (subject or "")
        if unicodedata.category(ch) not in ("Cf", "Co", "Cs")
    )
    text = " ".join(text.split())
    # No clickable link and no auto-linked domain: hxxps://login[.]evil[.]example
    text = _SCHEME.sub(lambda m: "hxx" + m.group(3), text)
    text = _DOMAIN_LIKE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    if len(text) > MAX_SUBJECT_CHARS:
        text = text[: MAX_SUBJECT_CHARS - 1] + "…"
    return text or "(no subject)"


@dataclass(frozen=True)
class ReportedEmail:
    subject: str
    verdict: Verdict
    label: str
    score: int
    advice: str
    reasons: list[str]


def _items(report: Report, settings: Settings) -> list[ReportedEmail]:
    rules = cached_rules(settings.rules_file or RULES_FILE).rules
    items = []
    for target in [report, *sorted(report.children, key=lambda r: str(r.id))]:
        verdict = target.final_verdict
        if verdict is None:
            continue
        reasons = []
        for finding in target.findings[:MAX_REASONS]:  # ordered by score, highest first
            rule = rules.get(finding.rule_id)
            reasons.append(rule.description if rule else finding.rule_id)
        items.append(
            ReportedEmail(
                subject=clean_subject(target.email.subject if target.email else None),
                verdict=verdict,
                label=VERDICT_LABELS[verdict.value],
                score=target.score or 0,
                advice=ADVICE[verdict],
                reasons=reasons,
            )
        )
    return items


def build_reply(report: Report, settings: Settings) -> EmailMessage:
    items = _items(report, settings)
    worst = min((i.verdict for i in items), key=_VERDICT_ORDER.index, default=None)
    headline = VERDICT_LABELS[worst.value] if worst else "Analysis complete"
    first = items[0].subject if items else "(no subject)"
    message = EmailMessage()
    message["From"] = settings.reply_from
    message["To"] = report.reporter_email or ""
    message["Subject"] = f"[PhishTriage] {headline}: {first}"
    message["Date"] = formatdate(localtime=False)
    domain = parseaddr(settings.reply_from)[1].rpartition("@")[2] or None
    message["Message-ID"] = make_msgid("phishtriage", domain=domain)
    if report.outer_message_id and _MESSAGE_ID.match(report.outer_message_id):
        message["In-Reply-To"] = report.outer_message_id
        message["References"] = report.outer_message_id
    # RFC 3834: an automatic reply. Mail systems must not auto-reply to it (no loops).
    message["Auto-Submitted"] = "auto-replied"
    message["X-Auto-Response-Suppress"] = "All"
    body = _env.get_template("reply.txt").render(
        items=items,
        inline=report.intake_mode == "inline",
        inline_hint=INLINE_HINT,
        reference=str(report.id),
    )
    message.set_content(body)
    return message


# --------------------------------------------------------------------------- sending

Sender = Callable[[Settings, EmailMessage], None]


def smtp_send(settings: Settings, message: EmailMessage) -> None:
    host, port = settings.smtp_host, settings.smtp_port
    context = ssl.create_default_context()
    smtp: smtplib.SMTP
    if settings.smtp_security == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS)
    with smtp:
        if settings.smtp_security == "starttls":
            smtp.starttls(context=context)
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password.get_secret_value())
        smtp.send_message(message)


def notify_reporter(
    session: Session, report: Report, settings: Settings, send: Sender = smtp_send
) -> bool:
    """Send the verdict to the reporter if the rules allow it. Returns whether one was sent.

    A failed send is recorded and logged but never fails the analysis.
    """
    if report.status is not ReportStatus.DONE:
        return False
    decision = decide(session, report, settings)
    if not decision.send:
        if decision.status != report.reply_status:
            report.reply_status = decision.status
            session.commit()
        if decision.status and decision.status != SENT:
            logger.info("report %s: reply %s", report.id, decision.status)
        return False
    message = build_reply(report, settings)
    try:
        send(settings, message)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("report %s: reply failed: %s", report.id, type(exc).__name__)
        report.reply_status = f"failed: {type(exc).__name__}"
        session.commit()
        return False
    report.reply_status = SENT
    report.replied_at = utcnow()
    session.commit()
    logger.info("report %s: reply sent", report.id)
    return True
