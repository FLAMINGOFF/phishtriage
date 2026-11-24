"""IOC export as a STIX 2.1 bundle (built and validated with the ``stix2`` library).

Every distinct indicator becomes one STIX Indicator whose ID is derived from its pattern
(UUIDv5), so exporting the same IOC twice yields the same ID and a threat-intel platform
de-duplicates it. Each exported report becomes a STIX Report that refers to its
indicators. Subjects and addresses of the reporters are not exported.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import stix2

from app import __version__
from app.export.iocs import IocRow

NAMESPACE = uuid.UUID("2b1f9e8e-4d0b-5c55-9e43-7a7f2b1c6a10")  # fixed: stable IDs
IDENTITY = stix2.Identity(
    id=f"identity--{uuid.uuid5(NAMESPACE, 'phishtriage')}",
    name="PhishTriage",
    identity_class="system",
    description="Suspicious-email triage platform (automated analysis and analyst review).",
)
_INDICATOR_TYPES = {
    "malicious": ["malicious-activity"],
    "suspicious": ["anomalous-activity"],
}


def _quote(value: str) -> str:
    """A STIX pattern string literal: backslashes and single quotes escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern_for(kind: str, value: str) -> str | None:
    if kind == "url":
        return f"[url:value = {_quote(value)}]"
    if kind == "domain":
        return f"[domain-name:value = {_quote(value)}]"
    if kind == "email":
        return f"[email-addr:value = {_quote(value)}]"
    if kind == "sha256":
        return f"[file:hashes.'SHA-256' = {_quote(value)}]"
    if kind == "ip":
        try:
            version = ipaddress.ip_address(value).version
        except ValueError:
            return None
        return f"[ipv{version}-addr:value = {_quote(value)}]"
    return None


def to_stix_bundle(rows: Iterable[IocRow]) -> stix2.Bundle:
    indicators: dict[str, dict[str, Any]] = {}
    reports: dict[uuid.UUID, dict[str, Any]] = {}
    for row in rows:
        pattern = pattern_for(row.type, row.value)
        if pattern is None:
            continue
        entry = indicators.setdefault(
            pattern,
            {"row": row, "first": row.received_at, "reports": set(), "verdicts": set()},
        )
        entry["first"] = min(entry["first"], row.received_at)
        entry["reports"].add(row.report_id)
        entry["verdicts"].add(row.verdict)
        report = reports.setdefault(row.report_id, {"received": row.received_at, "refs": []})
        indicator_id = f"indicator--{uuid.uuid5(NAMESPACE, pattern)}"
        if indicator_id not in report["refs"]:
            report["refs"].append(indicator_id)

    objects: list[Any] = [IDENTITY]
    for pattern, entry in indicators.items():
        first: IocRow = entry["row"]
        verdicts = entry["verdicts"]
        verdict = next((v for v in ("malicious", "suspicious") if v in verdicts), "unknown")
        objects.append(
            stix2.Indicator(
                id=f"indicator--{uuid.uuid5(NAMESPACE, pattern)}",
                created_by_ref=IDENTITY.id,
                name=f"{first.type} seen in reported email",
                description=(
                    f"Seen in {len(entry['reports'])} reported email(s); "
                    f"verdict: {', '.join(sorted(v or 'none' for v in verdicts))}."
                ),
                indicator_types=_INDICATOR_TYPES.get(verdict, ["unknown"]),
                pattern=pattern,
                pattern_type="stix",
                valid_from=entry["first"],
            )
        )
    for report_id, report in reports.items():
        received: datetime = report["received"]
        objects.append(
            stix2.Report(
                id=f"report--{uuid.uuid5(NAMESPACE, str(report_id))}",
                created_by_ref=IDENTITY.id,
                name=f"PhishTriage report {report_id}",
                report_types=["threat-report"],
                published=received,
                object_refs=report["refs"],
                description=f"Indicators from a reported email (PhishTriage {__version__}).",
            )
        )
    return stix2.Bundle(objects=objects)
