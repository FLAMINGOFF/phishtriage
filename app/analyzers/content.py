"""Content analyzer: what the text asks the reader to do (English and Chinese).

Keyword rules are crude on purpose: they are cheap, explainable and only worth a few
points each. The evidence shows the exact sentence fragment that matched.
"""

from __future__ import annotations

import re

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.parsing.defang import defang_text
from app.parsing.html import analyze_html

MAX_SCAN_CHARS = 200_000
# Up to N characters within one sentence; single line breaks are fine (plain-text mail is
# wrapped at ~72 columns), a blank line ends the search.
_GAP = r"(?:(?!\n[ \t\r]{{0,10}}\n)[^.!?]){{0,{n}}}"
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
        r"\b(?:verify|confirm|validate|re-?activate)\s+(?:your\s+)?"
        r"(?:identity|account|mailbox|e-?mail account|login)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bsign[- ]?in\b{_GAP.format(n=20)}\bto\s+(?:keep|avoid|continue|restore|verify|"
        r"unlock|prevent|reactivate)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:输入|提供|确认|验证|核实|更新|重置|填写|回复|保留)[^\n]{0,10}"
        r"(?:密码|口令|验证码|动态码|校验码|账号信息|登录信息|银行卡)"
    ),
    re.compile(r"(?:验证|确认|核实)(?:您的|你的)?(?:身份|账户|账号|邮箱)"),
]
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
    r"(?:\bnever|\bnot|n't|\bno one\b|绝不|不会|切勿|请勿|不要|永远不)[^.!?\n]{0,25}$",
    re.IGNORECASE,
)


def _text(ctx: AnalysisContext) -> list[tuple[str, str]]:
    email = ctx.email
    fields = [("Subject", email.subject), ("Body", email.body_text[:MAX_SCAN_CHARS])]
    if email.body_html:
        html_text = analyze_html(email.body_html[:MAX_SCAN_CHARS]).text
        if html_text.strip() and html_text.strip() not in email.body_text:
            fields.append(("HTML body", html_text))
    return fields


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - 40)
    right = min(len(text), end + 40)
    return " ".join(text[left:right].split())


def _find(fields: list[tuple[str, str]], patterns: list[re.Pattern[str]]) -> list[Evidence]:
    items = []
    for name, text in fields:
        for pattern in patterns:
            for match in pattern.finditer(text):
                if _NEGATION.search(text[max(0, match.start() - 30) : match.start()]):
                    continue
                snippet = defang_text(_snippet(text, match.start(), match.end()))
                items.append(evidence(name, snippet, " ".join(match.group(0).split())))
    return items


def analyze(ctx: AnalysisContext) -> list[Hit]:
    fields = _text(ctx)
    hits: list[Hit] = []
    if credentials := _find(fields, CREDENTIAL_PATTERNS):
        hits.append(hit("CONTENT_CREDENTIAL_REQUEST", credentials))
    if urgency := _find(fields, URGENCY_PATTERNS):
        hits.append(hit("CONTENT_URGENCY", urgency))  # counted once, however many phrases
    return hits
