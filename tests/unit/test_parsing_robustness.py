"""Mutated fixtures must parse or be rejected cleanly: never crash the worker."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from app.parsing.eml import MessageRejected, extract_originals
from app.parsing.html import sanitize_html
from app.parsing.iocs import extract_observables

FIXTURES = sorted((Path(__file__).parents[1] / "fixtures" / "emails").glob("*.eml"))
INSERTS = [
    b"=?utf-8?q?",
    b"\r\n",
    b"<",
    b'"',
    b"(",
    b"--",
    b";",
    b"=",
    b"\x00",
    b"@",
    b"[",
    b'boundary="x"',
    b"Content-Type: message/rfc822\r\n",
    b"\xff\xfe",
]


def mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 20)):
        pos = rng.randrange(len(buf))
        roll = rng.random()
        if roll < 0.5:
            buf[pos] = rng.randrange(256)
        elif roll < 0.75:
            del buf[pos : pos + rng.randint(1, 50)]
        else:
            buf[pos:pos] = rng.choice(INSERTS)
    return bytes(buf)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem[:2])
def test_mutations_never_crash(path: Path) -> None:
    rng = random.Random(path.name)  # noqa: S311 - deterministic fuzzing, not crypto
    data = path.read_bytes()
    for _ in range(40):
        try:
            intake = extract_originals(mutate(data, rng), is_report_wrapper=rng.random() < 0.5)
        except MessageRejected:
            continue
        for original in intake.originals:
            extract_observables(original, ["example.edu"])
            if original.body_html:
                sanitize_html(original.body_html)
