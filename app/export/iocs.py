"""Collect the indicators to export from a set of reports."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.db.models import IntelStatus, Report
from app.intel.models import PROVIDER_LABELS


@dataclass(frozen=True)
class IocRow:
    type: str
    value: str
    defanged: str
    report_id: uuid.UUID
    received_at: datetime
    verdict: str  # the analyst's verdict if there is one, else the automatic one
    intel: str  # e.g. "VirusTotal: 5/70 engines flag it malicious; URLhaus: listed"


def ioc_rows(reports: Iterable[Report]) -> list[IocRow]:
    rows = []
    for report in reports:
        verdict = report.final_verdict.value if report.final_verdict else ""
        for observable in report.observables:
            intel = "; ".join(
                f"{PROVIDER_LABELS[r.provider.value]}: {r.detail or r.status.value}"
                for r in observable.intel_results
                if r.status in (IntelStatus.HIT, IntelStatus.CLEAN)
            )
            rows.append(
                IocRow(
                    type=observable.type.value,
                    value=observable.value,
                    defanged=observable.defanged,
                    report_id=report.id,
                    received_at=report.received_at,
                    verdict=verdict,
                    intel=intel,
                )
            )
    return rows
