"""Statistics page: reports per week, verdict distribution, processing time.

Everything is computed in Python from one query per figure, so the same code runs on
SQLite (tests) and PostgreSQL (date arithmetic differs between the two). A SOC sees tens
or hundreds of reports a week, so a year of rows is small.

"Reports" are reported emails: a submission that attached three emails counts three
times, because each one got its own verdict. A report's verdict is the analyst's verdict
where there is one, otherwise the automatic one, the same rule as in the queue.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Report, ReportSource, ReportStatus, Verdict, utcnow
from app.scoring.engine import RULES_FILE, VERDICT_LABELS, cached_rules
from app.web.deps import get_session, require_user
from app.web.templating import templates

router = APIRouter(tags=["stats"], dependencies=[Depends(require_user)])

WEEK_CHOICES = (4, 12, 26, 52)
DEFAULT_WEEKS = 12
TOP_RULES = 10

# Bar chart geometry, in SVG user units (the SVG scales to the page width).
CHART_WIDTH = 640
CHART_HEIGHT = 160
CHART_TOP = 12  # room for the label above the tallest bar
BAR_SHARE = 0.65  # of each week's slot; the rest is the gap between bars
RADIUS = 3


@dataclass(frozen=True)
class WeekBar:
    start: date
    count: int
    x: float
    y: float
    width: float
    height: float
    path: str  # the bar with rounded top corners, anchored to the baseline

    @property
    def label(self) -> str:
        return f"{self.start:%b} {self.start.day}"


@dataclass(frozen=True)
class Share:
    key: str
    label: str
    count: int
    percent: float


@dataclass
class Stats:
    weeks: int
    since: datetime
    total: int = 0
    by_week: list[WeekBar] = field(default_factory=list)
    week_max: int = 0
    verdicts: list[Share] = field(default_factory=list)
    pending: int = 0
    failed: int = 0
    sources: list[Share] = field(default_factory=list)
    median_seconds: float | None = None
    p95_seconds: float | None = None
    mean_seconds: float | None = None
    reviewed: int = 0
    overruled: int = 0
    replies_sent: int = 0
    top_rules: list[tuple[str, str, int, float]] = field(default_factory=list)


def week_start(moment: datetime) -> date:
    """Monday of the (UTC) week ``moment`` falls in."""
    day = moment.astimezone(UTC).date() if moment.tzinfo else moment.date()
    return day - timedelta(days=day.weekday())


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile: a value that actually occurred, no interpolation."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def _bar_path(x: float, y: float, width: float, height: float) -> str:
    if height <= 0:
        return ""
    r = min(RADIUS, width / 2, height)
    bottom = y + height
    return (
        f"M{x:g},{bottom:g}V{y + r:g}Q{x:g},{y:g} {x + r:g},{y:g}"
        f"H{x + width - r:g}Q{x + width:g},{y:g} {x + width:g},{y + r:g}V{bottom:g}Z"
    )


def _bars(counts: Counter[date], first: date, weeks: int) -> tuple[list[WeekBar], int]:
    peak = max(counts.values(), default=0)
    scale = (CHART_HEIGHT - CHART_TOP) / peak if peak else 0
    slot = CHART_WIDTH / weeks
    width = round(slot * BAR_SHARE, 1)
    bars = []
    for i in range(weeks):
        start = first + timedelta(weeks=i)
        count = counts.get(start, 0)
        height = round(count * scale, 1)
        x = round(i * slot + (slot - width) / 2, 1)
        y = CHART_HEIGHT - height
        bars.append(WeekBar(start, count, x, y, width, height, _bar_path(x, y, width, height)))
    return bars, peak


def _shares(counter: Counter[str], labels: dict[str, str], order: list[str]) -> list[Share]:
    total = sum(counter.values())
    return [
        Share(key, labels.get(key, key), counter.get(key, 0), 100 * counter.get(key, 0) / total)
        for key in order
        if total
    ]


def compute_stats(
    session: Session,
    *,
    weeks: int,
    now: datetime | None = None,
    rules_file: Path | None = None,
) -> Stats:
    now = now or utcnow()
    first = week_start(now) - timedelta(weeks=weeks - 1)
    since = datetime.combine(first, time.min, tzinfo=UTC)
    stats = Stats(weeks=weeks, since=since)

    rows = session.execute(
        select(
            Report.received_at,
            Report.status,
            Report.source,
            Report.verdict,
            Report.analyst_verdict,
            Report.analyzed_at,
            Report.replied_at,
        ).where(Report.received_at >= since)
    ).all()
    stats.total = len(rows)

    per_week: Counter[date] = Counter()
    verdicts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    durations: list[float] = []
    for received, status, source, verdict, analyst, analyzed, replied in rows:
        per_week[week_start(received)] += 1
        sources[source.value] += 1
        if replied is not None:
            stats.replies_sent += 1
        if status is ReportStatus.FAILED:
            stats.failed += 1
            continue
        if status is not ReportStatus.DONE:
            stats.pending += 1
            continue
        final = analyst or verdict
        if final is not None:
            verdicts[final.value] += 1
        if analyst is not None:
            stats.reviewed += 1
            if analyst is not verdict:
                stats.overruled += 1
        if analyzed is not None:
            received_utc = received if received.tzinfo else received.replace(tzinfo=UTC)
            analyzed_utc = analyzed if analyzed.tzinfo else analyzed.replace(tzinfo=UTC)
            durations.append(max(0.0, (analyzed_utc - received_utc).total_seconds()))

    stats.by_week, stats.week_max = _bars(per_week, first, weeks)
    stats.verdicts = _shares(verdicts, VERDICT_LABELS, [v.value for v in Verdict])
    stats.sources = _shares(
        sources,
        {"imap": "Report mailbox", "upload": "Upload", "api": "API"},
        [s.value for s in ReportSource],
    )
    stats.median_seconds = percentile(durations, 0.5)
    stats.p95_seconds = percentile(durations, 0.95)
    stats.mean_seconds = sum(durations) / len(durations) if durations else None

    rule_rows = session.execute(
        select(Finding.rule_id, func.count(func.distinct(Finding.report_id)))
        .join(Report, Report.id == Finding.report_id)
        .where(Report.received_at >= since, Report.status == ReportStatus.DONE)
        .group_by(Finding.rule_id)
        .order_by(func.count(func.distinct(Finding.report_id)).desc(), Finding.rule_id)
        .limit(TOP_RULES)
    ).all()
    rules = cached_rules(rules_file or RULES_FILE).rules
    analysed = sum(verdicts.values())
    stats.top_rules = [
        (
            rule_id,
            rules[rule_id].description if rule_id in rules else "",
            count,
            100 * count / analysed if analysed else 0.0,
        )
        for rule_id, count in rule_rows
    ]
    return stats


def duration(seconds: float | None) -> str:
    """12 s, 3.5 min, 2.1 h: short, for a stat tile."""
    if seconds is None:
        return "-"
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 90 * 60:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


@router.get("/stats", response_class=HTMLResponse)
def stats_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    weeks: Annotated[int, Query(ge=1, le=52)] = DEFAULT_WEEKS,
) -> Response:
    if weeks not in WEEK_CHOICES:
        weeks = DEFAULT_WEEKS
    stats = compute_stats(session, weeks=weeks, rules_file=request.app.state.settings.rules_file)
    return templates.TemplateResponse(
        request,
        "stats.html",
        {
            "stats": stats,
            "week_choices": WEEK_CHOICES,
            "duration": duration,
            "chart": {"width": CHART_WIDTH, "height": CHART_HEIGHT, "slot": CHART_WIDTH / weeks},
        },
    )
