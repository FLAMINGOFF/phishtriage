"""rules.yaml and the scoring engine."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.analyzers.base import Evidence, Hit
from app.db.models import Verdict
from app.scoring.engine import RULES_FILE, RuleSet, UnknownRule, load_rules, score

# Rule IDs and analyzers are fixed by the project plan; points may be re-tuned.
PLAN_RULES = {
    "AUTH_DMARC_FAIL": "auth",
    "AUTH_SPF_FAIL": "auth",
    "AUTH_DKIM_FAIL": "auth",
    "AUTH_NO_TRUSTED_RESULTS": "auth",
    "SENDER_LOOKALIKE_DOMAIN": "sender",
    "SENDER_DISPLAY_NAME_SPOOF": "sender",
    "SENDER_FREEMAIL_IMPERSONATION": "sender",
    "SENDER_NEW_DOMAIN": "sender",
    "SENDER_REPLY_TO_MISMATCH": "sender",
    "URL_INTEL_MALICIOUS": "urls",
    "URL_CREDENTIAL_FORM": "urls",
    "URL_TEXT_HREF_MISMATCH": "urls",
    "URL_IP_HOST": "urls",
    "URL_PUNYCODE": "urls",
    "URL_SHORTENER": "urls",
    "ATT_INTEL_MALICIOUS": "attachments",
    "ATT_EXECUTABLE": "attachments",
    "ATT_EXT_MISMATCH": "attachments",
    "ATT_MACRO": "attachments",
    "ATT_HTML_FILE": "attachments",
    "ATT_ENCRYPTED_ARCHIVE": "attachments",
    "CONTENT_CREDENTIAL_REQUEST": "content",
    "CONTENT_URGENCY": "content",
}
ANALYZER_DIR = Path(__file__).parents[2] / "app" / "analyzers"


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


def ev(match: str = "m") -> Evidence:
    return Evidence(field="f", value="v", match=match)


def test_rules_file_matches_the_plan(rules: RuleSet) -> None:
    assert {rule_id: rule.analyzer for rule_id, rule in rules.rules.items()} == PLAN_RULES
    assert rules.thresholds.model_dump() == {"malicious": 70, "suspicious": 40, "low_risk": 15}
    assert rules.rules["AUTH_NO_TRUSTED_RESULTS"].score == 0
    assert rules.rules["AUTH_SPF_FAIL"].variants == {"softfail": 5}
    forced = {rule_id for rule_id, rule in rules.rules.items() if rule.forces_verdict}
    assert forced == {"URL_INTEL_MALICIOUS", "ATT_INTEL_MALICIOUS"}


def test_every_rule_is_raised_by_its_analyzer() -> None:
    for rule_id, analyzer in PLAN_RULES.items():
        source = (ANALYZER_DIR / f"{analyzer}.py").read_text(encoding="utf-8")
        assert f'"{rule_id}"' in source, f"{rule_id} not raised in {analyzer}.py"
    raised = set()
    for path in ANALYZER_DIR.glob("*.py"):
        raised |= set(re.findall(r'"((?:AUTH|SENDER|URL|ATT|CONTENT)_[A-Z_]+)"', path.read_text()))
    assert raised == set(PLAN_RULES)


@pytest.mark.parametrize(
    ("total", "verdict"),
    [
        (0, Verdict.NO_ISSUES),
        (14, Verdict.NO_ISSUES),
        (15, Verdict.LOW_RISK),
        (39, Verdict.LOW_RISK),
        (40, Verdict.SUSPICIOUS),
        (69, Verdict.SUSPICIOUS),
        (70, Verdict.MALICIOUS),
        (500, Verdict.MALICIOUS),
    ],
)
def test_verdict_bands(rules: RuleSet, total: int, verdict: Verdict) -> None:
    assert rules.verdict_for(total) is verdict


def test_score_adds_points_once_per_rule(rules: RuleSet) -> None:
    result = score(
        [
            Hit("AUTH_DMARC_FAIL", (ev("a"),)),
            Hit("URL_IP_HOST", (ev("b"),)),
            Hit("URL_IP_HOST", (ev("c"), ev("b"))),  # same rule again: evidence merged
            Hit("AUTH_NO_TRUSTED_RESULTS", (ev(),)),
        ],
        rules,
    )
    assert result.score == 45
    assert result.verdict is Verdict.SUSPICIOUS
    assert [f.rule_id for f in result.findings] == [
        "AUTH_DMARC_FAIL",
        "URL_IP_HOST",
        "AUTH_NO_TRUSTED_RESULTS",
    ]
    ip = next(f for f in result.findings if f.rule_id == "URL_IP_HOST")
    assert [e.match for e in ip.evidence] == ["b", "c"]
    assert ip.analyzer == "urls"
    assert ip.description


def test_variant_points(rules: RuleSet) -> None:
    soft = score([Hit("AUTH_SPF_FAIL", (ev(),), variant="softfail")], rules)
    assert soft.score == 5
    hard = score([Hit("AUTH_SPF_FAIL", (ev(),))], rules)
    assert hard.score == 10
    with pytest.raises(UnknownRule, match="no variant"):
        score([Hit("AUTH_SPF_FAIL", (ev(),), variant="neutral")], rules)


def test_intel_hit_forces_malicious(rules: RuleSet) -> None:
    result = score([Hit("URL_INTEL_MALICIOUS", (ev(),))], rules)
    assert result.score == 50
    assert result.verdict is Verdict.MALICIOUS
    assert result.forced_by == "URL_INTEL_MALICIOUS"


def test_unknown_rule_is_a_bug(rules: RuleSet) -> None:
    with pytest.raises(UnknownRule):
        score([Hit("NOT_A_RULE", (ev(),))], rules)


def test_no_hits(rules: RuleSet) -> None:
    result = score([], rules)
    assert (result.score, result.verdict, result.findings) == (0, Verdict.NO_ISSUES, ())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["rules"]["URL_IP_HOST"].update(points=3),  # unknown key
        lambda d: d["rules"]["URL_IP_HOST"].update(analyzer="magic"),
        lambda d: d["rules"]["URL_IP_HOST"].update(score=-5),
        lambda d: d["thresholds"].update(suspicious=80),  # out of order
        lambda d: d.update(version=2),
        lambda d: d.update(extra=True),
    ],
)
def test_invalid_rules_file_is_refused(tmp_path: Path, mutate) -> None:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_rules(path)


def test_tuned_copy_is_used(tmp_path: Path) -> None:
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    data["rules"]["URL_IP_HOST"]["score"] = 45
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    tuned = load_rules(path)
    assert score([Hit("URL_IP_HOST", (ev(),))], tuned).verdict is Verdict.SUSPICIOUS


def test_scoring_doc_lists_every_rule_with_its_points(rules: RuleSet) -> None:
    doc = (Path(__file__).parents[2] / "docs" / "scoring.md").read_text(encoding="utf-8")
    for rule_id, rule in rules.rules.items():
        row = next((line for line in doc.splitlines() if line.startswith(f"| `{rule_id}` |")), None)
        assert row is not None, f"{rule_id} missing from docs/scoring.md"
        assert f"| {rule.analyzer} | {rule.score}" in row, f"{rule_id}: points out of date"
