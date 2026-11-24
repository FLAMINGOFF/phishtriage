"""IOC export as CSV, safe to open in a spreadsheet."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from app.export.iocs import IocRow

COLUMNS = ["type", "value", "defanged", "report_id", "received_at", "verdict", "intel"]

# A cell starting with one of these is a formula in Excel, LibreOffice and Google Sheets.
# Attacker-chosen text (an email address such as "=HYPERLINK(...)@x") must stay text.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: str) -> str:
    return "'" + value if value.startswith(_FORMULA_START) else value


def to_csv(rows: Iterable[IocRow]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow(
            [
                _cell(row.type),
                _cell(row.value),
                _cell(row.defanged),
                str(row.report_id),
                row.received_at.isoformat(),
                _cell(row.verdict),
                _cell(row.intel),
            ]
        )
    return out.getvalue()
