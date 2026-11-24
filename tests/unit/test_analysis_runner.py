"""Analyzer isolation: time limits and failures never sink the whole analysis."""

from __future__ import annotations

import threading

import pytest

from app import analysis
from app.analyzers.base import AnalysisContext, Evidence, Hit
from app.analyzers.runner import ANALYZERS, run_analyzers
from app.config import Policy
from app.parsing.eml import parse_message
from tests.unit.analyzer_helpers import message


def test_all_five_analyzers_are_registered() -> None:
    assert list(ANALYZERS) == ["auth", "sender", "urls", "attachments", "content"]


def test_slow_and_broken_analyzers_are_contained(example_policy: Policy) -> None:
    parsed, _ = parse_message(message())
    ctx = AnalysisContext(email=parsed, policy=example_policy)
    release = threading.Event()

    def slow(_ctx: AnalysisContext) -> list[Hit]:
        release.wait(5)
        return [Hit("URL_IP_HOST", (Evidence(field="f", value="v", match="m"),))]

    def broken(_ctx: AnalysisContext) -> list[Hit]:
        raise RuntimeError("boom")

    def fine(_ctx: AnalysisContext) -> list[Hit]:
        return [Hit("CONTENT_URGENCY", (Evidence(field="f", value="v", match="m"),))]

    try:
        run = run_analyzers(
            ctx, {"urls": slow, "attachments": broken, "content": fine}, timeout=0.2
        )
    finally:
        release.set()
    assert [h.rule_id for h in run.hits] == ["CONTENT_URGENCY"]
    assert run.errors == {"urls": "timed out after 0.2 s", "attachments": "failed: RuntimeError"}


def test_partial_analysis_is_reported(
    example_policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def stuck(attachment):
        release.wait(5)
        raise AssertionError("unreachable in time")

    monkeypatch.setattr(analysis, "inspect_attachment", stuck)
    raw = message(attachments=[("a.exe", "application/octet-stream", b"MZ")])
    parsed, _ = parse_message(raw)
    try:
        result = analysis.analyze_email(parsed, example_policy, timeout=0.2)
    finally:
        release.set()
    assert result.errors == {"inspection": "timed out after 0.2 s"}
    assert result.error_summary == "partial analysis: inspection timed out after 0.2 s"
    assert result.attachments[0].detected_type is None
    assert "ATT_EXECUTABLE" in {f.rule_id for f in result.result.findings}  # name still counts


def test_inspection_failure(example_policy: Policy, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(attachment):
        raise ValueError("bad file")

    monkeypatch.setattr(analysis, "inspect_attachment", broken)
    parsed, _ = parse_message(message(attachments=[("a.pdf", "application/pdf", b"%PDF-1.4")]))
    result = analysis.analyze_email(parsed, example_policy)
    assert result.errors == {"inspection": "failed: ValueError"}
