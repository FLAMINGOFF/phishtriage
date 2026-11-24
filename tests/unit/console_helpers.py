"""Helpers for tests of the analyst console (login, CSRF tokens)."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

TEST_PASSWORD = "correct horse battery staple"
_CSRF = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')


def csrf_from(html: str) -> str:
    match = _CSRF.search(html)
    assert match, "no CSRF token in the page"
    return match.group(1)


def csrf(client: TestClient, page: str = "/login") -> str:
    """The CSRF token the console would put into a form for this browser."""
    return csrf_from(client.get(page).text)


def login(client: TestClient, email: str, password: str = TEST_PASSWORD) -> None:
    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
