"""Evaluation isolation, integrity, privacy and failure handling."""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

import pytest

from app.config import Policy
from app.db.models import Verdict
from scripts import evaluate as ev
from scripts import public_corpus as pc


def test_split_uses_raw_bytes_independent_of_label_and_order() -> None:
    samples = [ev.Sample("a", b"a", "ham"), ev.Sample("b", b"b", "phish")]
    first = {s.raw: pc.split_name(s.raw) for s in samples}
    assert first == {s.raw: pc.split_name(s.raw) for s in reversed(samples)}
    assert first == {b"a": "heldout", b"b": "dev"}  # SHA-256 ca... and 3e...
    assert pc.split_name(ev.Sample("renamed", b"a", "phish").raw) == first[b"a"]


def test_checksum_failure_precedes_parsing(tmp_path, monkeypatch) -> None:
    name = "nazario-phishing-2021.mbox"
    (tmp_path / name).write_bytes(b"modified corpus")
    monkeypatch.setattr(ev, "load", lambda *_: pytest.fail("must not parse unverified bytes"))
    with pytest.raises(ValueError, match="Checksum mismatch"):
        pc.load_source(tmp_path, name)


def test_dev_never_loads_extra_or_measures_heldout(tmp_path, monkeypatch) -> None:
    targets = {
        ("phish", "dev"): 58,
        ("phish", "heldout"): 43,
        ("ham", "dev"): 1395,
        ("ham", "heldout"): 1355,
    }
    counts: Counter[tuple[str, str]] = Counter()
    samples = []
    for label in ("phish", "ham"):
        i = 0
        while any(counts[(label, split)] < targets[(label, split)] for split in ("dev", "heldout")):
            raw = f"synthetic {label} {i}".encode()
            key = label, pc.split_name(raw)
            if counts[key] < targets[key]:
                samples.append(ev.Sample("private source", raw, label))
                counts[key] += 1
            i += 1

    def source(_directory, name):
        assert "2025" not in name
        return samples if name == "nazario-phishing-2021.mbox" else []

    def measure(group, _policy):
        assert len(group) == 1453
        assert all(pc.split_name(s.raw) == "dev" for s in group)
        return {"measured": len(group)}

    monkeypatch.setattr(pc, "load_source", source)
    monkeypatch.setattr(pc, "measured", measure)
    result = pc.run(tmp_path, "dev")
    assert set(result["runs"]) == {"dev"}
    assert "2025" not in str(result["metadata"]["corpora"])


def test_summary_does_not_leak_message_data_or_invent_positive_only_fpr() -> None:
    sample = ev.Sample("PRIVATE filename", b"SECRET raw message", "phish")
    report = ev.Report([ev.Outcome(sample, Verdict.LOW_RISK, 15, ("CONTENT_URGENCY",), False)])
    summary = pc.summarize(report)
    assert summary["metrics"]["false_positive_rate"] is None
    assert summary["metrics"]["precision"] is None
    assert "PRIVATE" not in str(summary)
    assert "SECRET" not in str(summary)
    assert summary["metrics"]["fn"] == 1


def test_rejected_analysis_cannot_be_published(monkeypatch, example_policy: Policy) -> None:
    sample = ev.Sample("x", b"x", "phish")
    report = ev.Report([ev.Outcome(sample, None, 0, (), False)])
    monkeypatch.setattr(ev, "evaluate", lambda *_: report)
    original = ev.analyze_email
    with pytest.raises(RuntimeError, match="Incomplete analysis"):
        pc.measured([sample], example_policy)
    assert ev.analyze_email is original


def test_partial_analysis_cannot_be_published(monkeypatch, example_policy: Policy) -> None:
    from tests.unit.analyzer_helpers import message

    result = SimpleNamespace(verdict=Verdict.NO_ISSUES, score=0, findings=[], forced_by=None)
    monkeypatch.setattr(
        ev,
        "analyze_email",
        lambda *_args, **_kwargs: SimpleNamespace(result=result, errors={"content": "timeout"}),
    )
    with pytest.raises(RuntimeError, match="Incomplete analysis"):
        pc.measured([ev.Sample("x", message(), "ham")], example_policy)


@pytest.mark.parametrize("event", ["socket.connect", "socket.getaddrinfo", "socket.sendto"])
def test_network_audit_hook_rejects_network(event: str) -> None:
    with pytest.raises(RuntimeError, match="Network access forbidden"):
        pc.offline(event, ())
    pc.offline("open", ())
