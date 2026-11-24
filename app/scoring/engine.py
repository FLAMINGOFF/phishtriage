"""Scoring engine: rule hits -> points -> verdict, driven by ``rules.yaml``.

The engine is deliberately dumb: points are additive, every rule counts at most once per
email, and a rule with ``forces_verdict`` (the ``*_INTEL_MALICIOUS`` rules) makes the
verdict malicious whatever the total. That keeps every verdict explainable as a list of
(rule ID, points, evidence).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.analyzers.base import AnalyzerName, Evidence, Hit
from app.db.models import Verdict

RULES_FILE = Path(__file__).with_name("rules.yaml")
# Never "safe": the best an automatic check can say is that it found nothing.
VERDICT_LABELS = {
    Verdict.MALICIOUS.value: "Malicious",
    Verdict.SUSPICIOUS.value: "Suspicious",
    Verdict.LOW_RISK.value: "Low risk",
    Verdict.NO_ISSUES.value: "No issues found",
}


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    analyzer: AnalyzerName
    score: int = Field(ge=0, le=100)
    description: str
    variants: dict[str, int] = Field(default_factory=dict)
    forces_verdict: Literal["malicious"] | None = None


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    malicious: int
    suspicious: int
    low_risk: int

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not 0 < self.low_risk < self.suspicious < self.malicious:
            raise ValueError("thresholds must satisfy 0 < low_risk < suspicious < malicious")
        return self


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    thresholds: Thresholds
    rules: dict[str, Rule]

    def verdict_for(self, score: int) -> Verdict:
        if score >= self.thresholds.malicious:
            return Verdict.MALICIOUS
        if score >= self.thresholds.suspicious:
            return Verdict.SUSPICIOUS
        if score >= self.thresholds.low_risk:
            return Verdict.LOW_RISK
        return Verdict.NO_ISSUES


class UnknownRule(ValueError):
    pass


def load_rules(path: Path = RULES_FILE) -> RuleSet:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return RuleSet.model_validate(data)


@lru_cache(maxsize=4)
def cached_rules(path: Path = RULES_FILE) -> RuleSet:
    return load_rules(path)


@dataclass(frozen=True)
class ScoredFinding:
    rule_id: str
    analyzer: str
    score: int
    description: str
    evidence: tuple[Evidence, ...]
    variant: str | None = None


@dataclass(frozen=True)
class ScoreResult:
    score: int
    verdict: Verdict
    findings: tuple[ScoredFinding, ...]
    forced_by: str | None = None  # rule that forced the verdict, if any


def score(hits: list[Hit], rules: RuleSet) -> ScoreResult:
    merged: dict[str, Hit] = {}
    for item in hits:
        if item.rule_id not in rules.rules:
            raise UnknownRule(f"analyzer raised unknown rule {item.rule_id!r}")
        if item.rule_id in merged:  # once per email: keep the first, merge the evidence
            first = merged[item.rule_id]
            merged[item.rule_id] = Hit(
                rule_id=first.rule_id,
                evidence=tuple(dict.fromkeys((*first.evidence, *item.evidence))),
                variant=first.variant if first.variant == item.variant else None,
            )
        else:
            merged[item.rule_id] = item

    findings = []
    forced_by = None
    for rule_id, item in merged.items():
        rule = rules.rules[rule_id]
        if item.variant is not None and item.variant not in rule.variants:
            raise UnknownRule(f"rule {rule_id} has no variant {item.variant!r}")
        points = rule.variants[item.variant] if item.variant is not None else rule.score
        findings.append(
            ScoredFinding(
                rule_id=rule_id,
                analyzer=rule.analyzer,
                score=points,
                description=rule.description,
                evidence=item.evidence,
                variant=item.variant,
            )
        )
        if rule.forces_verdict and forced_by is None:
            forced_by = rule_id
    findings.sort(key=lambda f: (-f.score, f.rule_id))
    total = sum(f.score for f in findings)
    verdict = Verdict.MALICIOUS if forced_by else rules.verdict_for(total)
    return ScoreResult(score=total, verdict=verdict, findings=tuple(findings), forced_by=forced_by)
