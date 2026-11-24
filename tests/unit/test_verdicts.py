"""M2 acceptance: every sample email gets its expected verdict, with evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.analysis import analyze_email
from app.config import Policy
from app.parsing.eml import extract_originals

ROOT = Path(__file__).parents[2]
EMAILS = ROOT / "tests" / "fixtures" / "emails"
EXPECTED: dict[str, list[str]] = yaml.safe_load(
    (ROOT / "tests" / "fixtures" / "expected_verdicts.yaml").read_text(encoding="utf-8")
)


def is_wrapper(name: str) -> bool:
    return "report" in name or "inline_forward" in name


def test_every_fixture_has_a_label() -> None:
    assert sorted(EXPECTED) == sorted(p.stem for p in EMAILS.glob("*.eml"))


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_verdict(name: str, example_policy: Policy) -> None:
    raw = (EMAILS / f"{name}.eml").read_bytes()
    intake = extract_originals(raw, is_report_wrapper=is_wrapper(name))
    verdicts = []
    for original in intake.originals:
        analysis = analyze_email(original, example_policy)
        assert analysis.errors == {}
        for finding in analysis.result.findings:
            assert finding.evidence, f"{finding.rule_id} has no evidence"
            for item in finding.evidence:
                assert item.field
                assert item.value
                assert item.match
        verdicts.append(analysis.result.verdict.value)
    assert verdicts == EXPECTED[name]
