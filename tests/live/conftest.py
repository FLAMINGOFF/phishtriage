"""Live tests call the real providers. They are deselected by default (``-m "not live"``).

Run them on purpose, with your own keys, to check that the providers still answer the way
the clients expect:

    VT_API_KEY=... URLHAUS_AUTH_KEY=... uv run pytest -m live tests/live
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def http_mock() -> None:
    """Replace the suite-wide respx router: these tests talk to the real APIs."""
