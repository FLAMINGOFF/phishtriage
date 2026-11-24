"""Jinja2 environment for the analyst console.

Autoescaping is on for every template: subjects, display names, file names and bodies are
attacker-controlled and are only ever rendered as text.
"""

from __future__ import annotations

import unicodedata
from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_DIR = Path(__file__).parent / "templates"


def visible(value: object) -> str:
    """Make invisible and direction-changing characters visible.

    A file name "invoice" + U+202E + "gpj.exe" renders as "invoiceexe.jpg"; shown as
    ``invoice<U+202E>gpj.exe`` the trick is obvious. Applied to file names and addresses.
    """
    text = "" if value is None else str(value)
    out = []
    for ch in text:
        category = unicodedata.category(ch)
        if category in ("Cf", "Cc", "Co", "Cs") and ch not in "\n\t":
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def timestamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def filesize(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"  # pragma: no cover


def build_templates() -> Jinja2Templates:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["visible"] = visible
    env.filters["timestamp"] = timestamp
    env.filters["filesize"] = filesize
    return Jinja2Templates(env=env)


templates = build_templates()
