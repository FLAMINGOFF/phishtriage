"""IOC export (CSV, STIX 2.1) and the "infected" ZIP for attachments."""

from __future__ import annotations

import csv
import io
import json
import shutil
import subprocess
import uuid
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
import stix2
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import audit
from app.db.models import AuditLog, Report
from app.export.csv_export import COLUMNS, to_csv
from app.export.infected_zip import infected_zip, safe_filename
from app.export.iocs import IocRow
from app.export.stix_export import pattern_for, to_stix_bundle
from tests.unit.console_helpers import csrf

Loader = Callable[[str], bytes]
WHEN = datetime(2026, 11, 24, 9, 30, tzinfo=UTC)


def row(kind: str, value: str, verdict: str = "malicious", **kw: object) -> IocRow:
    fields: dict[str, object] = {
        "type": kind,
        "value": value,
        "defanged": value.replace(".", "[.]"),
        "report_id": uuid.UUID(int=1),
        "received_at": WHEN,
        "verdict": verdict,
        "intel": "",
    }
    fields.update(kw)
    return IocRow(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- CSV


def test_csv_neutralises_formulas() -> None:
    rows = [
        row("email", '=HYPERLINK("https://evil.example","click")@evil.example'),
        row("url", "+cmd|' /C calc'!A0"),
        row("domain", "-2+3"),
        row("email", "@SUM(A1)"),
        row("url", 'https://ok.example/a,b"c'),
    ]
    parsed = list(csv.reader(io.StringIO(to_csv(rows))))
    assert parsed[0] == COLUMNS
    values = [r[1] for r in parsed[1:]]
    assert values[:4] == [
        '\'=HYPERLINK("https://evil.example","click")@evil.example',
        "'+cmd|' /C calc'!A0",
        "'-2+3",
        "'@SUM(A1)",
    ]
    assert values[4] == 'https://ok.example/a,b"c'  # quoting is the csv module's job
    assert parsed[1][4] == "2026-11-24T09:30:00+00:00"


# --------------------------------------------------------------------------- STIX


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("url", "https://evil.example/a'b\\c", "[url:value = 'https://evil.example/a\\'b\\\\c']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("email", "a@evil.example", "[email-addr:value = 'a@evil.example']"),
        ("sha256", "ab" * 32, f"[file:hashes.'SHA-256' = '{'ab' * 32}']"),
        ("ip", "192.0.2.1", "[ipv4-addr:value = '192.0.2.1']"),
        ("ip", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("ip", "not-an-ip", None),
        ("unknown", "x", None),
    ],
)
def test_stix_patterns(kind: str, value: str, expected: str | None) -> None:
    assert pattern_for(kind, value) == expected


def test_stix_bundle_parses_and_is_stable() -> None:
    other = uuid.UUID(int=2)
    rows = [
        row("url", "https://evil.example/login?a='1'"),
        row("domain", "evil.example"),
        row("domain", "evil.example", report_id=other, verdict="suspicious"),
        row("sha256", "cd" * 32),
        row("ip", "198.51.100.7", verdict="suspicious"),
        row("ip", "bogus"),  # skipped: no valid pattern
    ]
    text = to_stix_bundle(rows).serialize()
    bundle = stix2.parse(text, allow_custom=False)  # M4 acceptance: stix2 can parse it
    assert bundle.type == "bundle"
    by_type: dict[str, list] = {}
    for obj in bundle.objects:
        by_type.setdefault(obj.type, []).append(obj)
    assert len(by_type["identity"]) == 1
    assert len(by_type["indicator"]) == 4  # the shared domain once
    assert len(by_type["report"]) == 2
    domain = next(i for i in by_type["indicator"] if "domain-name" in i.pattern)
    assert domain.indicator_types == ["malicious-activity"]
    assert "Seen in 2 reported email(s)" in domain.description
    ip = next(i for i in by_type["indicator"] if "ipv4" in i.pattern)
    assert ip.indicator_types == ["anomalous-activity"]
    for report in by_type["report"]:
        assert all(ref.startswith("indicator--") for ref in report.object_refs)
    # Same input, same IDs: a threat-intel platform de-duplicates repeated exports.
    again = json.loads(to_stix_bundle(rows).serialize())
    assert {o["id"] for o in again["objects"]} == {o.id for o in bundle.objects}


def test_empty_stix_bundle_is_valid() -> None:
    bundle = stix2.parse(to_stix_bundle([]).serialize(), allow_custom=False)
    assert [o.type for o in bundle.objects] == ["identity"]


# --------------------------------------------------------------------------- export routes


@pytest.fixture
def client(app_factory: Callable[..., FastAPI], console) -> TestClient:
    return console(app_factory())


def upload(client: TestClient, content: bytes) -> uuid.UUID:
    response = client.post(
        "/upload",
        files={"file": ("x.eml", content)},
        data={"csrf_token": csrf(client, "/upload")},
        follow_redirects=False,
    )
    return uuid.UUID(response.headers["location"].rsplit("/", 1)[1])


def exports(session_factory) -> list[AuditLog]:
    with session_factory() as session:
        return list(
            session.scalars(
                select(AuditLog)
                .where(AuditLog.action.in_([audit.EXPORT_CSV, audit.EXPORT_STIX]))
                .order_by(AuditLog.created_at)
            )
        )


def test_report_exports(client: TestClient, fixture_bytes: Loader, session_factory) -> None:
    report_id = upload(client, fixture_bytes("02"))
    response = client.get(f"/reports/{report_id}/iocs.csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="phishtriage-{report_id}.csv"'
    )
    parsed = list(csv.DictReader(io.StringIO(response.text)))
    assert parsed
    assert {r["report_id"] for r in parsed} == {str(report_id)}
    assert {r["verdict"] for r in parsed} == {"malicious"}
    urls = [r for r in parsed if r["type"] == "url"]
    assert urls
    assert all("[.]" in r["defanged"] for r in urls)

    response = client.get(f"/reports/{report_id}/iocs.stix.json")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/stix+json;version=2.1"
    bundle = stix2.parse(response.text, allow_custom=False)
    patterns = [o.pattern for o in bundle.objects if o.type == "indicator"]
    assert any(p.startswith("[url:value") for p in patterns)
    assert "Mailbox quota exceeded" not in response.text  # subjects are not exported

    logged = exports(session_factory)
    assert [e.action for e in logged] == [audit.EXPORT_CSV, audit.EXPORT_STIX]
    assert all(e.report_id == report_id and e.details["reports"] == 1 for e in logged)
    assert logged[0].details["indicators"] == len(parsed)
    assert client.get(f"/reports/{uuid.uuid4()}/iocs.csv").status_code == 404


def test_bulk_exports(client: TestClient, fixture_bytes: Loader, session_factory) -> None:
    phish = upload(client, fixture_bytes("02"))
    benign = upload(client, fixture_bytes("11"))
    old = upload(client, fixture_bytes("01"))
    with session_factory() as session:
        report = session.get(Report, old)
        assert report is not None
        assert report.final_verdict is not None
        report.received_at = report.received_at - timedelta(days=40)
        session.commit()

    response = client.get("/exports/iocs.csv")  # default: malicious + suspicious, 30 days
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith(
        'attachment; filename="phishtriage-iocs-'
    )
    report_ids = {r["report_id"] for r in csv.DictReader(io.StringIO(response.text))}
    assert report_ids == {str(phish)}

    response = client.get("/exports/iocs.csv", params={"verdict": "no_issues"})
    assert {r["report_id"] for r in csv.DictReader(io.StringIO(response.text))} <= {str(benign)}

    response = client.get("/exports/iocs.stix.json", params={"days": 60})
    bundle = stix2.parse(response.text, allow_custom=False)
    reports = [o for o in bundle.objects if o.type == "report"]
    assert len(reports) == 2  # the phish and the 40-day-old report

    assert client.get("/exports/iocs.csv", params={"days": 0}).status_code == 422
    assert client.get("/exports/iocs.csv", params={"days": 366}).status_code == 422
    assert client.get("/exports/iocs.csv", params={"verdict": "bogus"}).status_code == 422

    logged = exports(session_factory)
    assert len(logged) == 3
    assert logged[0].details == {
        "reports": 1,
        "indicators": logged[0].details["indicators"],
        "verdicts": ["malicious", "suspicious"],
        "days": 30,
    }
    assert logged[0].report_id is None


# --------------------------------------------------------------------------- infected ZIP


@pytest.mark.parametrize("size", [0, 1, 1000, 300_000])
def test_infected_zip_round_trip(size: int) -> None:
    content = bytes((n * 7 + n // 13) % 256 for n in range(size))
    archive = infected_zip("sample.bin", content)
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        [info] = zf.infolist()
        assert info.filename == "sample.bin"
        assert info.flag_bits & 0x1
        assert info.date_time == (1980, 1, 1, 0, 0, 0)
        assert info.file_size == size
        with pytest.raises(RuntimeError, match="password"):
            zf.read(info, pwd=b"wrong")
        assert zf.read(info, pwd=b"infected") == content


def test_infected_zip_is_not_plaintext() -> None:
    marker = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    archive = infected_zip("eicar.com", marker)
    assert marker not in archive  # mail filters and scanners see nothing to block


@pytest.mark.skipif(shutil.which("unzip") is None, reason="unzip is not installed")
def test_infected_zip_opens_with_unzip(tmp_path) -> None:
    unzip = shutil.which("unzip")
    assert unzip is not None
    path = tmp_path / "a.zip"
    path.write_bytes(infected_zip("note.txt", b"hello\n" * 100))
    out = subprocess.run(  # noqa: S603 - fixed arguments, a file we just wrote
        [unzip, "-P", "infected", "-p", str(path)], capture_output=True, check=True
    )
    assert out.stdout == b"hello\n" * 100


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("invoice.pdf", "invoice.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\evil.exe", "evil.exe"),
        ("invoice\u202egpj.exe", "invoicegpj.exe"),
        ("a\x00b\nc.txt", "abc.txt"),
        ('what?*:"<>|.doc', "what_______.doc"),
        ("...hidden", "hidden"),
        ("", "attachment"),
        ("../", "attachment"),
        ("\u5408\u540c.docx", "\u5408\u540c.docx"),
        ("a" * 300, "a" * 150),
    ],
)
def test_safe_filename(name: str, expected: str) -> None:
    assert safe_filename(name) == expected
