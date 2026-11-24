#!/usr/bin/env python3
"""Fill the database with demo reports spread over the last weeks. Synthetic data only.

    docker compose run --rm seed                                 # the Compose demo
    uv run python scripts/seed_demo.py --count 150 --weeks 12   # a development database

Every report is one of the generated sample emails in ``tests/fixtures/emails/``, made
unique with a demo header and run through the real pipeline (offline: no intel lookups),
so verdicts, rules and evidence are exactly what PhishTriage computes. What is simulated:

* when each report arrived (business hours over the last ``--weeks`` weeks) and how long
  the worker took (a few seconds to a few minutes), so the statistics page has a history;
* who reported it: mailbox reports come from made-up ``@example.edu`` employees, wrapped
  the way ``scripts/send_sample.py`` wraps them ("Forward as attachment");
* review work by ``demo.analyst@example.edu``: confirmed or changed verdicts and a few
  notes, written to the audit log like real ones. The account gets a random password
  that nobody knows, so it cannot be used to log in.

No reply is sent for demo reports; their reply status says so. The script refuses to run
twice unless ``--again`` is given.
"""

from __future__ import annotations

import argparse
import random
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app import audit  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db.models import (  # noqa: E402
    Report,
    ReportSource,
    ReportStatus,
    User,
    UserRole,
    Verdict,
    utcnow,
)
from app.db.session import get_sessionmaker  # noqa: E402
from app.pipeline import process, submit  # noqa: E402
from app.storage import BlobStore  # noqa: E402
from app.web.auth import hash_password  # noqa: E402
from scripts.send_sample import build_report  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "emails"
DEMO_ANALYST = "demo.analyst@example.edu"
REPORTERS = [
    f"{name}@example.edu"
    for name in (
        "alice",
        "bob",
        "carol",
        "dan",
        "erin",
        "grace",
        "heidi",
        "ivan",
        "judy",
        "oscar",
        "peggy",
        "trent",
        "victor",
        "wendy",
    )
]
# Fixtures that already are reports from an employee (the original is attached or
# forwarded inline): they go to the mailbox as they are.
REPORT_FIXTURES = {"06", "07", "08", "13"}
BENIGN_FIXTURES = {"04", "05", "11", "12"}
NOTES = [
    "Confirmed with the reporter: nobody clicked the link.",
    "Sender domain blocked at the mail gateway.",
    "Same campaign as last week; IOCs exported to the firewall team.",
    "Legitimate vendor mail, the user did not expect it.",
    "Asked the reporter to change their password as a precaution.",
]


def fixture_files() -> dict[str, Path]:
    return {path.name[:2]: path for path in sorted(FIXTURES.glob("*.eml"))}


def pick_fixture(rng: random.Random, files: dict[str, Path]) -> str:
    """About 40 % legitimate mail: employees report plenty of harmless email too."""
    pool = sorted(BENIGN_FIXTURES if rng.random() < 0.4 else set(files) - BENIGN_FIXTURES)
    return rng.choice(pool)


def arrival(rng: random.Random, now: datetime, weeks: int) -> datetime:
    """A moment in business hours (07:00-18:00 UTC, Monday to Friday) in the period,
    slightly more often recent than old."""
    while True:
        days = int(weeks * 7 * rng.random() ** 1.3)
        day = (now - timedelta(days=days)).date()
        if day.weekday() < 5:
            break
    moment = datetime(day.year, day.month, day.day, 7, tzinfo=UTC) + timedelta(
        seconds=rng.randrange(11 * 3600)
    )
    return min(moment, now - timedelta(minutes=5))


def worker_seconds(rng: random.Random) -> float:
    """Mostly 5-40 s; one report in ten waits for the VirusTotal rate limit."""
    return rng.uniform(60, 240) if rng.random() < 0.1 else rng.uniform(5, 40)


def demo_analyst(session: Session) -> User:
    user = User(
        email=DEMO_ANALYST,
        password_hash=hash_password(secrets.token_urlsafe(32)),  # never shown, never used
        role=UserRole.ANALYST,
    )
    session.add(user)
    session.commit()
    return user


def review(
    session: Session, rng: random.Random, report: Report, analyst: User, now: datetime
) -> None:
    """Simulate an analyst: confirm most verdicts, change a few, leave some notes."""
    if report.verdict is None or report.analyzed_at is None:
        return
    reviewed_at = report.analyzed_at + timedelta(minutes=rng.uniform(10, 600))
    if reviewed_at > now or rng.random() > 0.45:
        return
    verdict = report.verdict
    if rng.random() < 0.12:  # the analyst disagrees with the rules
        verdict = {
            Verdict.LOW_RISK: Verdict.SUSPICIOUS,
            Verdict.SUSPICIOUS: Verdict.MALICIOUS,
            Verdict.NO_ISSUES: Verdict.LOW_RISK,
            Verdict.MALICIOUS: Verdict.MALICIOUS,
        }[verdict]
    report.analyst_verdict = verdict
    report.closed_at = reviewed_at
    entry = audit.record(
        session,
        audit.REPORT_RECLASSIFY,
        user=analyst,
        report_id=report.id,
        previous=None,
        verdict=verdict.value,
        automatic=report.verdict.value,
        score=report.score,
    )
    entry.created_at = reviewed_at
    if rng.random() < 0.3:
        note = audit.record(
            session, audit.REPORT_NOTE, user=analyst, report_id=report.id, text=rng.choice(NOTES)
        )
        note.created_at = reviewed_at + timedelta(minutes=2)


def seed(
    session: Session,
    store: BlobStore,
    *,
    count: int,
    weeks: int,
    rng: random.Random,
    now: datetime | None = None,
    again: bool = False,
) -> int:
    """Create ``count`` demo submissions. Returns how many reports (emails) were created."""
    settings = get_settings()
    now = now or utcnow()
    analyst = session.scalar(select(User).where(User.email == DEMO_ANALYST))
    if analyst is not None and not again:
        raise SystemExit("demo data is already there (use --again to add more)")
    analyst = analyst or demo_analyst(session)
    files = fixture_files()
    created = 0
    for number in range(count):
        key = pick_fixture(rng, files)
        sample = files[key].read_bytes()
        stamp = f"X-PhishTriage-Demo: {number} {secrets.token_hex(4)}\r\n".encode()
        reporter = rng.choice(REPORTERS)
        roll = rng.random()
        if key in REPORT_FIXTURES:
            source, raw = ReportSource.IMAP, stamp + sample
        elif roll < 0.7:
            source = ReportSource.IMAP
            _, raw = build_report(
                sample,
                reporter=reporter,
                mailbox="report-phishing@example.edu",
                authserv_id="mx.example.edu",
                inline=False,
            )
        else:
            source = ReportSource.UPLOAD if roll < 0.9 else ReportSource.API
            raw = stamp + sample
        received = arrival(rng, now, weeks)
        report = submit(session, store, raw, source=source, received_at=received)
        session.commit()
        root = process(session, store, report.id, settings.policy, rules_file=settings.rules_file)
        took = timedelta(seconds=worker_seconds(rng))
        family = [root, *session.scalars(select(Report).where(Report.parent_id == root.id))]
        for item in family:
            if item.status is ReportStatus.DONE:
                item.analyzed_at = received + took
            if item.source is ReportSource.IMAP and item.parent_id is None:
                item.reply_status = "not sent: demo data (scripts/seed_demo.py)"
            review(session, rng, item, analyst, now)
            created += 1
        session.commit()
    return created


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=150, help="submissions (default 150)")
    parser.add_argument("--weeks", type=int, default=12, help="spread over N weeks (default 12)")
    parser.add_argument("--seed", type=int, default=2026, help="random seed (default 2026)")
    parser.add_argument("--again", action="store_true", help="add more even if seeded before")
    args = parser.parse_args(argv)
    if not 1 <= args.count <= 5000 or not 1 <= args.weeks <= 52:
        parser.error("--count must be 1-5000 and --weeks 1-52")
    settings = get_settings()
    with get_sessionmaker()() as session:
        created = seed(
            session,
            BlobStore(settings.storage_dir),
            count=args.count,
            weeks=args.weeks,
            rng=random.Random(args.seed),  # noqa: S311 - demo data, not security
            again=args.again,
        )
    print(f"created {created} demo report(s) from {args.count} submission(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
