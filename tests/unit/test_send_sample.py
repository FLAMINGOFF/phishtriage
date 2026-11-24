"""scripts/send_sample.py builds the report an employee would send."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingest.imap_poller import message_id
from app.parsing.eml import extract_originals
from scripts import send_sample

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "credential-phish.eml"


def test_report_carries_the_sample_as_an_attachment() -> None:
    sample = SAMPLE.read_bytes()
    sent_id, raw = send_sample.build_report(
        sample,
        reporter="alice@example.edu",
        mailbox="report-phishing@example.edu",
        authserv_id="mx.example.edu",
        inline=False,
    )
    assert message_id(raw) == sent_id
    intake = extract_originals(raw, is_report_wrapper=True)
    assert intake.mode == "attachment"
    assert intake.outer.from_addr is not None
    assert intake.outer.from_addr.address == "alice@example.edu"
    [header] = intake.outer.authentication_results
    assert header.authserv_id == "mx.example.edu"
    assert {r.method: r.result for r in header.results}["dmarc"] == "pass"
    [original] = intake.originals
    assert original.subject == "Action required: verify your account"
    assert sample.rstrip(b"\r\n") in raw  # attached byte for byte


def test_inline_forward_and_no_auth_header() -> None:
    _, raw = send_sample.build_report(
        SAMPLE.read_bytes(),
        reporter="bob@example.edu",
        mailbox="report-phishing@example.edu",
        authserv_id=None,
        inline=True,
    )
    assert b"Authentication-Results" not in raw
    intake = extract_originals(raw, is_report_wrapper=True)
    assert intake.mode == "inline"
    assert "Forwarded message" in intake.originals[0].body_text


def test_main_sends_every_sample(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    sent: list[tuple[str, int, str, str, bytes]] = []
    monkeypatch.setattr(send_sample, "send", lambda *args: sent.append(args))
    assert send_sample.main(["--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    samples = sorted(p.name for p in send_sample.SAMPLES.glob("*.eml"))
    assert sorted(item["file"] for item in printed) == samples
    assert {args[:4] for args in sent} == {
        ("127.0.0.1", 3025, "alice@example.edu", "report-phishing@example.edu")
    }


def test_wait_for_replies(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    listing = {"messages": [{"ID": "m1", "Subject": "[PhishTriage] Malicious: x"}, {"ID": "m2"}]}
    headers = {"m1": {"In-Reply-To": ["<a@example.edu>"]}, "m2": {}}

    def fake_get(url: str) -> object:
        if url.endswith("/headers"):
            return headers[url.split("/")[-2]]
        return listing

    monkeypatch.setattr(send_sample, "_get_json", fake_get)
    monkeypatch.setattr(send_sample.time, "sleep", lambda _s: None)
    assert send_sample.wait_for_replies("http://mailpit", {"<a@example.edu>": "a.eml"}, 5)
    assert "reply for a.eml: [PhishTriage] Malicious: x" in capsys.readouterr().out
    assert not send_sample.wait_for_replies("http://mailpit", {"<b@example.edu>": "b.eml"}, 0)
    assert "no reply for b.eml" in capsys.readouterr().err


def test_every_fixture_can_be_wrapped() -> None:
    """Including the deliberately broken ones (unknown charset, malformed headers)."""
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "emails"
    for path in sorted(fixtures.glob("*.eml")):
        for inline in (False, True):
            _, raw = send_sample.build_report(
                path.read_bytes(),
                reporter="alice@example.edu",
                mailbox="report-phishing@example.edu",
                authserv_id="mx.example.edu",
                inline=inline,
            )
            assert extract_originals(raw, is_report_wrapper=True).originals, path.name
