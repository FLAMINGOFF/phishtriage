"""End to end against the running Compose stack: report by email, get the verdict back.

M5 acceptance: within one minute of sending a sample, its report is ``done`` and Mailpit
has the reply; a report from an address outside the organisation gets no reply.

Needs ``docker compose up`` with ``API_TOKEN`` set, then::

    PHISHTRIAGE_BASE_URL=http://127.0.0.1:8000 PHISHTRIAGE_API_TOKEN=... \\
        uv run pytest -m integration tests/integration
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from scripts import send_sample

# Read at import: the autouse settings fixture clears the application's variables.
BASE_URL = os.environ.get("PHISHTRIAGE_BASE_URL", "").rstrip("/")
API_TOKEN = os.environ.get("PHISHTRIAGE_API_TOKEN") or os.environ.get("API_TOKEN", "")
MAILPIT = os.environ.get("MAILPIT_URL", "http://127.0.0.1:8025").rstrip("/")
SMTP_HOST = os.environ.get("REPORT_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.environ.get("REPORT_SMTP_PORT", "3025"))
SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "credential-phish.eml"
DEADLINE_SECONDS = 60

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not BASE_URL, reason="PHISHTRIAGE_BASE_URL is not set"),
]


def get_json(url: str, token: str | None = None) -> object:
    request = urllib.request.Request(url)  # noqa: S310 - the test stack's own URL
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        return json.load(response)


def report_for(message_id: str) -> dict | None:
    query = urllib.parse.urlencode({"message_id": message_id})
    found = get_json(f"{BASE_URL}/api/reports?{query}", API_TOKEN)
    assert isinstance(found, list)
    roots = [r for r in found if r["parent_id"] is None]
    return roots[0] if roots else None


def mailpit_replies(reporter: str) -> dict[str, str]:
    """{In-Reply-To: subject} of every message Mailpit holds for ``reporter``."""
    query = urllib.parse.urlencode({"query": f"to:{reporter}"})
    listing = get_json(f"{MAILPIT}/api/v1/search?{query}")
    replies = {}
    for message in listing.get("messages", []) if isinstance(listing, dict) else []:
        headers = get_json(f"{MAILPIT}/api/v1/message/{message['ID']}/headers")
        for value in headers.get("In-Reply-To", []) if isinstance(headers, dict) else []:
            replies[value] = message.get("Subject", "")
    return replies


def report_by_mail(reporter: str) -> str:
    message_id, raw = send_sample.build_report(
        SAMPLE.read_bytes(),
        reporter=reporter,
        mailbox="report-phishing@example.edu",
        authserv_id="mx.example.edu",
        inline=False,
    )
    send_sample.send(SMTP_HOST, SMTP_PORT, reporter, "report-phishing@example.edu", raw)
    return message_id


def wait_until_done(message_id: str, started: float) -> dict:
    while time.monotonic() - started < DEADLINE_SECONDS:
        report = report_for(message_id)
        if report and report["status"] in ("done", "failed"):
            return report
        time.sleep(1)
    pytest.fail(f"report for {message_id} not done within {DEADLINE_SECONDS} s")


def test_internal_reporter_gets_the_verdict_within_a_minute() -> None:
    assert API_TOKEN, "set PHISHTRIAGE_API_TOKEN (the stack's API_TOKEN)"
    reporter = f"e2e-{int(time.time())}@example.edu"
    started = time.monotonic()
    message_id = report_by_mail(reporter)
    report = wait_until_done(message_id, started)
    assert report["status"] == "done"
    assert report["verdict"] == "malicious"
    assert report["reporter_email"] == reporter
    while message_id not in (replies := mailpit_replies(reporter)):
        assert time.monotonic() - started < DEADLINE_SECONDS, "no reply in Mailpit"
        time.sleep(1)
    assert replies[message_id].startswith("[PhishTriage] Malicious: ")
    assert report_for(message_id)["reply_status"] == "sent"  # type: ignore[index]


def test_external_reporter_gets_no_reply() -> None:
    reporter = f"e2e-{int(time.time())}@external.example"
    started = time.monotonic()
    message_id = report_by_mail(reporter)
    report = wait_until_done(message_id, started)
    assert report["status"] == "done"
    assert report["reply_status"] == "not sent: reporter outside the organisation"
    assert mailpit_replies(reporter) == {}
