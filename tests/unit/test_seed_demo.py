"""scripts/seed_demo.py: demo reports through the real pipeline, spread over weeks."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app import audit
from app.db.models import AuditLog, Report, ReportSource, ReportStatus, User
from app.web.routes.stats import compute_stats
from scripts import seed_demo

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def aware(moment: datetime) -> datetime:
    """SQLite gives naive datetimes back; they are UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def test_seed_creates_analysed_reports_over_the_period(session_factory, store) -> None:
    with session_factory() as session:
        rng = random.Random(7)  # noqa: S311 - test data
        created = seed_demo.seed(session, store, count=40, weeks=4, rng=rng, now=NOW)
        reports = session.scalars(select(Report)).all()
        assert created == len(reports) >= 40
        assert all(r.status is ReportStatus.DONE for r in reports)
        assert all(r.findings or r.verdict is not None for r in reports)
        assert {r.source for r in reports} >= {ReportSource.IMAP, ReportSource.UPLOAD}
        for r in reports:
            received = aware(r.received_at)
            assert NOW - timedelta(weeks=4, days=1) <= received <= NOW
            assert received.weekday() < 5
            assert r.analyzed_at is not None
            took = (aware(r.analyzed_at) - received).total_seconds()
            assert 5 <= took <= 240
        mailbox = [r for r in reports if r.source is ReportSource.IMAP and r.parent_id is None]
        assert mailbox
        assert all(r.reporter_email.endswith("@example.edu") for r in mailbox)
        assert all(r.reply_status.startswith("not sent: demo data") for r in mailbox)
        analyst = session.scalar(select(User).where(User.email == seed_demo.DEMO_ANALYST))
        assert analyst is not None
        reviews = session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == audit.REPORT_RECLASSIFY, AuditLog.user_id == analyst.id)
        )
        reviewed = [r for r in reports if r.analyst_verdict is not None]
        assert reviews == len(reviewed) > 0
        assert all(r.closed_at is not None and aware(r.closed_at) <= NOW for r in reviewed)

        stats = compute_stats(session, weeks=5, now=NOW)  # 4 weeks back reach into a 5th
        assert stats.total == len(reports)
        assert stats.median_seconds is not None
        assert stats.median_seconds < 60
        assert sum(1 for bar in stats.by_week if bar.count) >= 3

        with pytest.raises(SystemExit, match="already there"):
            seed_demo.seed(session, store, count=1, weeks=4, rng=rng, now=NOW)
        more = seed_demo.seed(session, store, count=2, weeks=4, rng=rng, now=NOW, again=True)
        assert more >= 2


def test_main_checks_its_arguments() -> None:
    with pytest.raises(SystemExit):
        seed_demo.main(["--count", "0"])


def test_main_uses_the_configured_database(
    session_factory, store, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(seed_demo, "get_sessionmaker", lambda: session_factory)
    monkeypatch.setenv("STORAGE_DIR", str(store.root))
    assert seed_demo.main(["--count", "3", "--weeks", "2"]) == 0
    assert "demo report(s) from 3 submission(s)" in capsys.readouterr().out
