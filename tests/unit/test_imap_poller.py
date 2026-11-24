from __future__ import annotations

import imaplib
import threading
from pathlib import Path
from typing import ClassVar

import pytest

from app.ingest import imap_poller


class FakeIMAP:
    """Stands in for imaplib.IMAP4; records what the poller did."""

    error = imaplib.IMAP4.error  # the real exception class, captured before patching
    instances: ClassVar[list[FakeIMAP]] = []

    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host, self.port, self.kwargs = host, port, kwargs
        self.calls: list[str] = []
        self.login_error: Exception | None = None
        self.select_result: tuple[str, list] = ("OK", [b"3"])
        FakeIMAP.instances.append(self)

    def login(self, user: str, password: str) -> tuple[str, list]:
        self.calls.append(f"login {user} {password}")
        if self.login_error:
            raise self.login_error
        return "OK", [b"logged in"]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list]:
        self.calls.append(f"select {mailbox} readonly={readonly}")
        return self.select_result

    def logout(self) -> tuple[str, list]:
        self.calls.append("logout")
        return "BYE", [b""]


@pytest.fixture
def fake_imap(monkeypatch: pytest.MonkeyPatch) -> type[FakeIMAP]:
    FakeIMAP.instances = []
    monkeypatch.setattr(imap_poller.imaplib, "IMAP4", FakeIMAP)
    monkeypatch.setattr(imap_poller.imaplib, "IMAP4_SSL", FakeIMAP)
    return FakeIMAP


@pytest.fixture
def settings(make_settings):
    return make_settings(imap_host="greenmail", imap_password="pw", poll_interval_seconds=5)


def test_counts_messages_read_only(fake_imap, settings) -> None:
    assert imap_poller.count_waiting(settings) == 3
    conn = fake_imap.instances[0]
    assert conn.calls == [
        "login report-phishing@example.edu pw",
        "select INBOX readonly=True",
        "logout",
    ]
    assert conn.kwargs["timeout"] == imap_poller.IMAP_TIMEOUT_SECONDS


def test_tls_connection_verifies_certificates(fake_imap, make_settings) -> None:
    imap_poller.count_waiting(make_settings(imap_ssl=True, imap_port=993))
    context = fake_imap.instances[0].kwargs["ssl_context"]
    assert context.verify_mode.name == "CERT_REQUIRED"
    assert context.check_hostname


def test_logout_even_when_login_fails(fake_imap, settings, monkeypatch) -> None:
    original_init = FakeIMAP.__init__

    def failing_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.login_error = imaplib.IMAP4.error("authentication failed")

    monkeypatch.setattr(FakeIMAP, "__init__", failing_init)
    with pytest.raises(imaplib.IMAP4.error):
        imap_poller.count_waiting(settings)
    assert fake_imap.instances[0].calls[-1] == "logout"


def test_bad_mailbox(fake_imap, settings, monkeypatch) -> None:
    original_init = FakeIMAP.__init__

    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.select_result = ("NO", [b"no such mailbox"])

    monkeypatch.setattr(FakeIMAP, "__init__", init)
    with pytest.raises(imap_poller.MailboxError):
        imap_poller.count_waiting(settings)


def test_poll_once_writes_heartbeat(fake_imap, settings, tmp_path: Path) -> None:
    beat = tmp_path / "hb"
    assert imap_poller.poll_once(settings, beat) == 3
    assert beat.exists()


def test_run_survives_errors_and_stops(settings, tmp_path: Path, monkeypatch) -> None:
    stop = threading.Event()
    calls = []

    def flaky(_settings, _heartbeat):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("connection refused")
        stop.set()
        return 0

    monkeypatch.setattr(imap_poller, "poll_once", flaky)
    monkeypatch.setattr(stop, "wait", lambda _timeout: stop.is_set())
    imap_poller.run(settings, stop, tmp_path / "hb")
    assert len(calls) == 2


def test_failed_poll_leaves_no_heartbeat(fake_imap, settings, tmp_path: Path, monkeypatch) -> None:
    def broken(_settings):
        raise OSError("down")

    monkeypatch.setattr(imap_poller, "count_waiting", broken)
    stop = threading.Event()
    monkeypatch.setattr(stop, "wait", lambda _timeout: stop.set())
    imap_poller.run(settings, stop, tmp_path / "hb")
    assert not (tmp_path / "hb").exists()
