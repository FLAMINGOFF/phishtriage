"""Golden-file tests: every synthetic fixture parses to its recorded summary.

After an intended parser change, regenerate with ``UPDATE_SNAPSHOTS=1 uv run pytest
tests/unit/test_snapshots.py`` and review the JSON diff like code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.cli import analyze_file
from app.config import Policy

ROOT = Path(__file__).parents[2]
EMAILS = ROOT / "tests" / "fixtures" / "emails"
SNAPSHOTS = ROOT / "tests" / "fixtures" / "snapshots"
FIXTURES = sorted(EMAILS.glob("*.eml"))


def is_wrapper(path: Path) -> bool:
    """Fixtures that arrive through the report mailbox (a reporter's message)."""
    return "report" in path.stem or "inline_forward" in path.stem


def test_there_are_fourteen_fixtures() -> None:
    assert len(FIXTURES) == 14


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture_snapshot(path: Path, example_policy: Policy) -> None:
    result = analyze_file(path.read_bytes(), example_policy, wrapper=is_wrapper(path))
    text = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    snapshot = SNAPSHOTS / f"{path.stem}.json"
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(text, encoding="utf-8")
    assert snapshot.exists(), f"missing {snapshot.name}: run with UPDATE_SNAPSHOTS=1"
    assert json.loads(snapshot.read_text(encoding="utf-8")) == json.loads(text)


def test_fixtures_match_generator() -> None:
    result = subprocess.run(  # noqa: S603 - fixed arguments, our own script
        [sys.executable, str(ROOT / "scripts" / "generate_emails.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_fixtures_use_reserved_domains_only() -> None:
    """Red line: no real people or organisations in the repository's sample mail."""
    import re

    allowed = re.compile(
        r"(?:^|\.)(?:example|invalid|test|localhost|example\.(?:com|net|org|edu))$"
    )
    domain = re.compile(rb"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
    for path in FIXTURES:
        for match in domain.finditer(path.read_bytes()):
            host = match.group(1).decode().lower().rstrip(".")
            assert allowed.search(host), f"{path.name}: {host}"
