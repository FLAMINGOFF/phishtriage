"""Statistics page: reports per week, verdicts, processing time, rules."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app.db.models import Finding, Report, ReportSource, ReportStatus, Verdict
from app.web.routes import stats

NOW = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)  # a Wednesday


def add_report(
    session,
    days_ago: float,
    *,
    verdict: Verdict | None = Verdict.MALICIOUS,
    analyst: Verdict | None = None,
    status: ReportStatus = ReportStatus.DONE,
    seconds: float = 30,
    source: ReportSource = ReportSource.IMAP,
    rules: tuple[str, ...] = (),
    replied: bool = False,
) -> Report:
    received = NOW - timedelta(days=days_ago)
    report = Report(
        id=uuid.uuid4(),
        source=source,
        received_at=received,
        status=status,
        verdict=verdict if status is ReportStatus.DONE else None,
        analyst_verdict=analyst,
        analyzed_at=received + timedelta(seconds=seconds) if status is ReportStatus.DONE else None,
        replied_at=received + timedelta(seconds=seconds) if replied else None,
        submission_sha256="0" * 64,
        submission_size=1,
    )
    session.add(report)
    for rule in rules:
        session.add(
            Finding(report_id=report.id, rule_id=rule, analyzer="content", score=5, evidence=[])
        )
    return report


def test_week_start_and_percentile() -> None:
    assert stats.week_start(NOW) == date(2026, 11, 23)
    assert stats.week_start(datetime(2026, 11, 23, 0, 0, tzinfo=UTC)) == date(2026, 11, 23)
    assert stats.week_start(datetime(2026, 11, 22, 23, 59, tzinfo=UTC)) == date(2026, 11, 16)
    assert stats.percentile([], 0.5) is None
    assert stats.percentile([5, 1, 3], 0.5) == 3
    assert stats.percentile([float(i) for i in range(1, 101)], 0.95) == 95
    assert stats.duration(None) == "-"
    assert stats.duration(12) == "12 s"
    assert stats.duration(300) == "5.0 min"
    assert stats.duration(4 * 3600) == "4.0 h"


def test_compute_stats(session_factory) -> None:
    with session_factory() as session:
        add_report(session, 0.5, seconds=20, rules=("CONTENT_URGENCY", "URL_SHORTENER"))
        add_report(session, 1, verdict=Verdict.NO_ISSUES, seconds=40, replied=True)
        add_report(
            session,
            2,
            verdict=Verdict.LOW_RISK,
            analyst=Verdict.MALICIOUS,
            seconds=60,
            rules=("CONTENT_URGENCY",),
        )
        add_report(
            session,
            3,
            verdict=Verdict.SUSPICIOUS,
            analyst=Verdict.SUSPICIOUS,
            seconds=600,
            source=ReportSource.UPLOAD,
        )
        add_report(session, 9, status=ReportStatus.FAILED, source=ReportSource.API)
        add_report(session, 0.1, status=ReportStatus.QUEUED)
        add_report(session, 200)  # outside every period
        session.commit()
        result = stats.compute_stats(session, weeks=4, now=NOW)

    assert result.since == datetime(2026, 11, 2, tzinfo=UTC)
    assert result.total == 6
    assert (result.pending, result.failed) == (1, 1)
    assert [b.start for b in result.by_week] == [
        date(2026, 11, 2),
        date(2026, 11, 9),
        date(2026, 11, 16),
        date(2026, 11, 23),
    ]
    # This week (Mon 23 to Wed 25) holds the reports 0.1, 0.5, 1 and 2 days old; the
    # week of the 16th the ones 3 days (Sunday) and 9 days (Monday) old.
    assert [b.count for b in result.by_week] == [0, 0, 2, 4]
    assert result.week_max == 4
    tallest = result.by_week[-1]
    assert tallest.height == stats.CHART_HEIGHT - stats.CHART_TOP
    assert tallest.path.startswith("M")
    assert result.by_week[0].path == ""

    shares = {s.key: s.count for s in result.verdicts}
    # The analyst's verdict wins: the low-risk one counts as malicious.
    assert shares == {"malicious": 2, "suspicious": 1, "low_risk": 0, "no_issues": 1}
    assert sum(s.percent for s in result.verdicts) == pytest.approx(100)
    assert {s.key: s.count for s in result.sources} == {"imap": 4, "upload": 1, "api": 1}
    assert (result.reviewed, result.overruled) == (2, 1)
    assert result.replies_sent == 1
    assert result.median_seconds == 40
    assert result.p95_seconds == 600
    assert result.mean_seconds == pytest.approx((20 + 40 + 60 + 600) / 4)
    assert result.top_rules[0][:3] == (
        "CONTENT_URGENCY",
        result.top_rules[0][1],
        2,
    )
    assert result.top_rules[0][1]  # the rule's description from rules.yaml
    assert result.top_rules[0][3] == pytest.approx(50)


def test_empty_database(session_factory) -> None:
    with session_factory() as session:
        result = stats.compute_stats(session, weeks=12, now=NOW)
    assert result.total == 0
    assert len(result.by_week) == 12
    assert result.week_max == 0
    assert result.verdicts == []
    assert result.top_rules == []
    assert result.median_seconds is None


def test_stats_page(app_factory, console, session_factory) -> None:
    client = console(app_factory())
    with session_factory() as session:
        add_report(session, 0, rules=("URL_SHORTENER",))
        session.commit()
    page = client.get("/stats")
    assert page.status_code == 200
    assert "Reported emails per week" in page.text
    assert "URL_SHORTENER" in page.text
    assert 'class="badge badge-malicious"' in page.text
    # CSP: no inline script or style, only files from our origin.
    assert page.text.count("<script") == page.text.count('<script src="/static/')
    assert "style=" not in page.text
    # An unknown period falls back to the default instead of failing.
    assert client.get("/stats?weeks=7").status_code == 200
    assert client.get("/stats?weeks=0").status_code == 422
    empty = console(app_factory(), email="new@example.edu")
    assert "Statistics" in empty.get("/reports").text  # in the navigation
