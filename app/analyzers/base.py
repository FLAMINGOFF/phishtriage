"""Types shared by the five analyzers.

An analyzer is a pure function ``analyze(ctx) -> list[Hit]``. A hit names a rule ID from
``app/scoring/rules.yaml`` and carries its evidence; the scoring engine, not the analyzer,
decides how many points that is. Evidence always has the same shape: the field that was
looked at, its value, and what matched. Indicator values in evidence are stored defanged,
because evidence is for display (console, reply); raw values live in ``observables``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.config import Policy
from app.intel.models import EMPTY_SNAPSHOT, IntelSnapshot
from app.parsing.attachments import AttachmentFacts
from app.parsing.defang import defang
from app.parsing.eml import ParsedEmail

AnalyzerName = Literal["auth", "sender", "urls", "attachments", "content"]
IndicatorKind = Literal["url", "domain", "ip", "email"]

MAX_EVIDENCE_ITEMS = 10
MAX_EVIDENCE_CHARS = 500


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    field: str
    value: str
    match: str


def evidence(
    field_name: str,
    value: str,
    match: str,
    *,
    kind: IndicatorKind | None = None,
    match_kind: IndicatorKind | None = None,
) -> Evidence:
    """Build one evidence item; ``kind``/``match_kind`` defang indicator values."""
    if kind is not None:
        value = defang(value, kind)
    if match_kind is not None:
        match = defang(match, match_kind)
    return Evidence(
        field=field_name[:100],
        value=value[:MAX_EVIDENCE_CHARS],
        match=match[:MAX_EVIDENCE_CHARS],
    )


@dataclass(frozen=True)
class Hit:
    """A rule matched. A rule fires at most once per email; all evidence is kept."""

    rule_id: str
    evidence: tuple[Evidence, ...]
    variant: str | None = None  # e.g. "softfail" for AUTH_SPF_FAIL


def hit(rule_id: str, items: list[Evidence], variant: str | None = None) -> Hit:
    unique = list(dict.fromkeys(items))  # Evidence is frozen, hence hashable
    return Hit(rule_id=rule_id, evidence=tuple(unique[:MAX_EVIDENCE_ITEMS]), variant=variant)


@dataclass(frozen=True)
class AnalysisContext:
    email: ParsedEmail
    policy: Policy
    attachments: tuple[AttachmentFacts, ...] = ()
    intel: IntelSnapshot = EMPTY_SNAPSHOT
    now: datetime | None = None  # "today" for domain-age rules; None means skip them


Analyzer = Callable[[AnalysisContext], list[Hit]]
