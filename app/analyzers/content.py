"""Content analyzer: what the text asks the reader to do (English and Chinese).

These bounded heuristics are explainable but incomplete. The evidence shows the
normalised sentence fragment that matched, including statically read HTML attachments.
"""

from __future__ import annotations

import re
import unicodedata

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.analyzers.html_content import MAX_SCAN_CHARS, html_documents
from app.parsing.defang import defang_text

# Up to N characters within one sentence; single line breaks are fine (plain-text mail is
# wrapped at ~72 columns), a blank line ends the search.
_GAP = r"(?:(?!\n[ \t\r]{{0,10}}\n)[^.!?;。]){{0,{n}}}"
_ASKED_FOR = (
    r"(?:password|passcode|passwd|pass code|pin(?: code)?|credentials|login details|"
    r"sign-in details|verification code|security code|one[- ]time (?:code|password|passcode)|"
    r"otp|mfa code|2fa code|authentication code|authenticator code|bank details)"
)
_ASK = (
    r"(?:verify|confirm|validate|update|re-?enter|enter|type|provide|submit|reset|keep|"
    r"send|share|reply with|re-?activate|unlock|restore)"
)
CREDENTIAL_PATTERNS = [
    re.compile(rf"\b{_ASK}\b{_GAP.format(n=40)}\b{_ASKED_FOR}\b", re.IGNORECASE),
    re.compile(
        rf"\b(?:sign|log)[- ]?in\b{_GAP.format(n=30)}\b(?:password|passcode|credentials)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:输入|提供|确认|验证|核实|更新|重置|填写|回复|保留)[^\n]{0,10}"
        r"(?:密码|口令|验证码|动态码|校验码|账号信息|登录信息|银行卡)"
    ),
    re.compile(r"(?:验证|确认|核实)(?:您的|你的)?(?:身份|账户|账号|邮箱)"),
]
# Ordinary account requests need independent evidence in the same clause.
_ACCOUNT_REQUESTS = [
    re.compile(
        r"\b(?:verify|confirm|validate|re-?activate|update)\s+(?:your\s+)?"
        r"(?:(?:e-?mail\s+)?(?:address|account|mailbox)|identity|login|security settings)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bsign[- ]?in\b{_GAP.format(n=20)}\bto\s+(?:keep|avoid|continue|restore|verify|"
        r"unlock|prevent|reactivate)\b",
        re.IGNORECASE,
    ),
    # Account-access requests are often nominal/passive rather than "verify password".
    re.compile(
        r"\b(?:account|mailbox|e-?mail|identity)\s+(?:re[- ]?)?verification\s+"
        r"(?:is\s+)?(?:required|needed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:mail\s?box|account)\b{_GAP.format(n=25)}"
        r"\b(?:needs? to be|must be)\s+(?:re[- ]?)?verified\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:log|sign)[ -]?(?:in|on)\s+(?:to|with|using|your)\b{_GAP.format(n=45)}"
        r"\b(?:password|mailbox|e-?mail|account|invoice|document)\b",
        re.IGNORECASE,
    ),
]
_CLAUSE_BREAK = re.compile(r"[.!?;。]|\n[ \t\r]*\n")
_ACCOUNT_CONTEXT = re.compile(
    rf"\b(?:{_ASKED_FOR}|within\s+(?:the\s+next\s+)?(?:\d{{1,3}}|one|an?)\s+"
    r"(?:minutes?|hours?|hrs?|days?)|by\s+(?:midnight|noon|tonight|tomorrow)|"
    r"(?:before|by)\s+the\s+end\s+of\s+(?:the\s+day|today)|"
    r"(?:los(?:e|ing)|denied)\s+(?:your\s+)?access|"
    r"(?:account|mailbox|access)\s+(?:(?:will|may)\s+be|is|has\s+been)\s+"
    r"(?:suspended|disabled|closed|deactivated|terminated|locked|deleted|blocked|restricted)|"
    r"(?:avoid|prevent)\s+(?:account\s+)?(?:suspension|deactivation|closure)|"
    r"keep\s+(?:(?:your\s+)?(?:account|mailbox)\s+active|receiving\s+(?:your\s+)?(?:e-?)?mail))\b",
    re.IGNORECASE,
)
URGENCY_PATTERNS = [
    re.compile(
        r"\b(?:urgent(?:ly)?|immediately|right away|as soon as possible|action required|"
        r"final (?:notice|warning|reminder)|last (?:notice|warning|chance)|"
        r"(?:expires?|due|ends?) (?:today|tonight)|"
        r"within \d{1,3} (?:hours?|hrs?|days?|minutes?))\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:account|mailbox|access|password|salary|payment|parcel|card)\b{_GAP.format(n=40)}"
        r"\b(?:will be|has been|is being|is)\s+(?:\w+\s+)?(?:suspended|disabled|closed|"
        r"deactivated|terminated|locked|deleted|blocked|delayed|on hold|restricted|expired?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:紧急|立即|马上|尽快|\d{1,3}\s*小时内|今天内|今日内|最后通知|"
        r"将被(?:停用|冻结|注销|关闭|删除|锁定|暂停)|即将(?:停用|过期|失效|冻结|注销))"
    ),
]
# "We will never ask for your password" is advice, not a request.
_NEGATION = re.compile(
    r"(?:\bnever\b|\bnot\b|n't\b|\bno one\b|绝不|不会|切勿|请勿|不要|永远不)"
    r"[^.!?:;。\n]{0,25}$",
    re.IGNORECASE,
)
_REASSURANCE = re.compile(
    r"\bno\s+(?:action|(?:account\s+)?verification)\s+"
    r"(?:is\s+)?(?:needed|required)\b(?:[ \t]+to[ \t]+)?",
    re.IGNORECASE,
)
# Reassurance applies to this credential only, even if a later deadline is genuine.
_CREDENTIAL_DISCLAIMER = re.compile(
    rf"\b(?:no\s+{_ASKED_FOR}\s+(?:(?:is|are)\s+)?(?:required|needed)|"
    rf"without\s+(?:an?\s+|your\s+)?{_ASKED_FOR}|"
    rf"{_ASKED_FOR}\s+(?:is|are)\s+not\s+(?:required|needed))\b",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    # Remove invisible format controls, not spaces/punctuation (sentence boundaries
    # remain significant). Compatibility forms include full-width Latin characters.
    return "".join(
        ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf"
    )


def _text(ctx: AnalysisContext) -> list[tuple[str, str]]:
    email = ctx.email
    fields = [("Subject", email.subject), ("Body", email.body_text[:MAX_SCAN_CHARS])]
    for name, document in html_documents(ctx):
        if document.text.strip() and document.text.strip() not in email.body_text:
            fields.append((name, document.text))
    return [(name, _normalize(text)) for name, text in fields]


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 40)
    right = min(len(text), end + 40)
    return " ".join(text[left:right].split())


def _negated(text: str, start: int) -> bool:
    if _NEGATION.search(text[max(0, start - 40) : start]):
        return True
    # "No account verification is required" overlaps the request itself.
    return any(
        phrase.start() <= start <= phrase.end()
        for phrase in _REASSURANCE.finditer(text, max(0, start - 64), min(len(text), start + 64))
    )


def _disclaimed_credential(text: str, end: int) -> bool:
    return any(
        phrase.start() < end <= phrase.end()
        for phrase in _CREDENTIAL_DISCLAIMER.finditer(text, max(0, end - 50), end + 32)
    )


def _account_context(text: str, request: re.Match[str]) -> re.Match[str] | None:
    # A subject, another sentence or a distant part of the email cannot lend its
    # deadline to a routine sign-in. Keep the qualifying words in the evidence.
    start, end = request.span()
    if _CLAUSE_BREAK.search(text, start, end):
        return None
    left = max(0, start - 80)
    for boundary in _CLAUSE_BREAK.finditer(text, left, start):
        left = boundary.end()
    right = min(len(text), end + 80)
    if following_break := _CLAUSE_BREAK.search(text, end, right):
        right = following_break.start()
    for cue in _ACCOUNT_CONTEXT.finditer(text, left, right):
        if not _disclaimed_credential(text, cue.end()):
            return cue
    return None


def _find(
    fields: list[tuple[str, str]], patterns: list[re.Pattern[str]], *, require_context: bool = False
) -> list[Evidence]:
    items = []
    for name, text in fields:
        for pattern in patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                if _negated(text, start):
                    continue
                if require_context:
                    context = _account_context(text, match)
                    if context is None:
                        continue
                    start, end = min(start, context.start()), max(end, context.end())
                elif _disclaimed_credential(text, end):
                    continue
                snippet = defang_text(_snippet(text, start, end))
                items.append(evidence(name, snippet, " ".join(match.group(0).split())))
    return items


def analyze(ctx: AnalysisContext) -> list[Hit]:
    fields = _text(ctx)
    hits: list[Hit] = []
    credentials = _find(fields, CREDENTIAL_PATTERNS)
    credentials.extend(_find(fields, _ACCOUNT_REQUESTS, require_context=True))
    if credentials:
        hits.append(hit("CONTENT_CREDENTIAL_REQUEST", credentials))
    if urgency := _find(fields, URGENCY_PATTERNS):
        hits.append(hit("CONTENT_URGENCY", urgency))  # counted once, however many phrases
    return hits
