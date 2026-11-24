"""scripts/evaluate.py: metrics, input formats and the fixture run."""

from __future__ import annotations

import json
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.db.models import Verdict
from scripts import evaluate


def outcome(label: str, verdict: Verdict, score: int, *rules: str) -> evaluate.Outcome:
    sample = evaluate.Sample(source="x", raw=b"", label=label)
    return evaluate.Outcome(sample, verdict, score, rules, forced=False)


def test_metrics_and_sweep() -> None:
    report = evaluate.Report(
        [
            outcome("phish", Verdict.MALICIOUS, 80, "A"),
            outcome("phish", Verdict.SUSPICIOUS, 45, "A", "B"),
            outcome("phish", Verdict.LOW_RISK, 30, "B"),
            outcome("ham", Verdict.NO_ISSUES, 0),
            outcome("ham", Verdict.SUSPICIOUS, 40, "B"),
            outcome("ham", Verdict.NO_ISSUES, 5),
            outcome("ham", Verdict.NO_ISSUES, 10),
        ]
    )
    m = report.metrics()
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 3)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(1 / 4)
    swept = report.metrics(30)
    assert (swept["tp"], swept["fp"]) == (3, 1)
    assert report.confusion()["phish"][Verdict.LOW_RISK] == 1
    rates = {rule: (hp, hh) for rule, hp, hh, _sp, _sh in report.rule_rates()}
    assert rates == {"A": (2, 0), "B": (2, 1)}
    assert evaluate.Report().metrics()["precision"] == 0.0


def _message(subject: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = "someone@sender.example"
    msg["To"] = "alice@example.edu"
    msg["Subject"] = subject
    msg.set_content("Hello.\n")
    return msg.as_bytes()


def test_loads_files_directories_and_mbox(tmp_path: Path) -> None:
    (tmp_path / "ham").mkdir()
    (tmp_path / "ham" / "00001.abc").write_bytes(_message("one"))
    (tmp_path / "ham" / "cmds").write_text("ignored")
    (tmp_path / "ham" / ".hidden").write_text("ignored")
    mbox = tmp_path / "phish.mbox"
    mbox.write_bytes(
        b"From x@y Mon Jan  1 00:00:00 2024\n"
        + _message("a")
        + b"\nFrom x@y Mon Jan  1 00:00:01 2024\n"
        + _message("b")
    )
    ham = list(evaluate.load([tmp_path / "ham"], "ham"))
    phish = list(evaluate.load([mbox], "phish"))
    assert [s.source for s in ham] == ["00001.abc"]
    assert [s.source for s in phish] == ["phish.mbox#0", "phish.mbox#1"]
    assert b"Subject: b" in phish[1].raw


def test_fixture_run_matches_the_labels(capsys) -> None:
    assert evaluate.main(["--fixtures"]) == 0
    text = capsys.readouterr().out
    assert "precision 100.0%  recall 100.0%" in text
    assert "fixtures with an unexpected verdict" not in text


def test_corpus_run_markdown_and_json(tmp_path: Path, capsys) -> None:
    ham = tmp_path / "ham.eml"
    ham.write_bytes(_message("Library opening hours"))
    phish = tmp_path / "phish.eml"
    phish.write_bytes(
        _message("Urgent: verify your password now").replace(
            b"Hello.",
            b"Your account will be suspended. Verify your password at http://192.0.2.7/login",
        )
    )
    out_json = tmp_path / "metrics.json"
    code = evaluate.main(
        [
            "--phish",
            str(phish),
            "--ham",
            str(ham),
            "--markdown",
            "--json",
            str(out_json),
            "--trust-authserv",
            "mx.sender.example",
        ]
    )
    assert code == 0
    markdown = capsys.readouterr().out
    assert markdown.startswith("| Emails | Precision | Recall |")
    assert "| Phishing |" in markdown
    assert "`CONTENT_CREDENTIAL_REQUEST`" in markdown
    payload = json.loads(out_json.read_text())
    assert payload["metrics"]["phish"] == 1
    assert payload["metrics"]["ham"] == 1
    assert payload["confusion"]["ham"] == {"no_issues": 1}


def test_rejected_messages_are_counted(tmp_path: Path, monkeypatch, capsys) -> None:
    from app.parsing.eml import MessageRejected

    def reject(*_args, **_kwargs):
        raise MessageRejected("too big")

    monkeypatch.setattr(evaluate, "extract_originals", reject)
    path = tmp_path / "a.eml"
    path.write_bytes(_message("x"))
    assert evaluate.main(["--ham", str(path), "--show-errors", "3"]) == 0
    assert "rejected by the parser: 1" in capsys.readouterr().out


def test_needs_an_input() -> None:
    with pytest.raises(SystemExit):
        evaluate.main([])
