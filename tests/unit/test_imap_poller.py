"""IMAP poller: fetch, de-duplicate, store, queue and move reports from the mailbox."""

from __future__ import annotations

import imaplib
import threading
from pathlib import Path
from typing import ClassVar

import pytest
from sqlalchemy import select

from app.db.models import Report, ReportSource, ReportStatus
from app.ingest import imap_poller
from app.ingest.imap_poller import Intake, message_id
from app.queueing import QueueUnavailable


def raw_message(n: int, *, with_id: bool = True) -> bytes:
    header = f"Message-ID: <report-{n}@example.edu>\r\n" if with_id else ""
    return (
        f"From: alice@example.edu\r\nTo: report-phishing@example.edu\r\n{header}"
        f"Subject: Fwd: suspicious {n}\r\n\r\nPlease check.\r\n"
    ).encode()


class FakeServer:
    """An in-memory mailbox server: folders of {uid: message}, plus flags."""

    def __init__(self, capabilities: tuple[str, ...] = ("IMAP4REV1", "MOVE", "UIDPLUS")) -> None:
        self.capabilities = capabilities
        self.folders: dict[str, dict[int, bytes]] = {"INBOX": {}}
        self.deleted: set[tuple[str, int]] = set()
        self.next_uid = 1
        self.commands: list[str] = []

    def deliver(self, *messages: bytes) -> None:
        for raw in messages:
            self.folders["INBOX"][self.next_uid] = raw
            self.next_uid += 1


class FakeIMAP:
    """Stands in for imaplib.IMAP4 / IMAP4_SSL, talking to a FakeServer."""

    error = imaplib.IMAP4.error  # the real exception class, captured before patching
    server: ClassVar[FakeServer]
    instances: ClassVar[list[FakeIMAP]] = []

    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host, self.port, self.kwargs = host, port, kwargs
        self.capabilities = ("IMAP4REV1",)  # before login; the poller asks again after
        self.selected: str | None = None
        self.calls: list[str] = []
        self.login_error: Exception | None = None
        FakeIMAP.instances.append(self)

    @staticmethod
    def _name(quoted: str) -> str:
        return quoted.strip('"')

    def login(self, user: str, password: str) -> tuple[str, list]:
        self.calls.append(f"login {user} {password}")
        if self.login_error:
            raise self.login_error
        return "OK", [b"logged in"]

    def capability(self) -> tuple[str, list]:
        return "OK", [" ".join(self.server.capabilities).encode()]

    def create(self, mailbox: str) -> tuple[str, list]:
        name = self._name(mailbox)
        self.calls.append(f"create {name}")
        if name in self.server.folders:
            return "NO", [b"[ALREADYEXISTS] mailbox exists"]
        self.server.folders[name] = {}
        return "OK", [b"created"]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list]:
        name = self._name(mailbox)
        self.calls.append(f"select {name}")
        if name not in self.server.folders:
            return "NO", [b"no such mailbox"]
        self.selected = name
        return "OK", [str(len(self.server.folders[name])).encode()]

    def uid(self, command: str, *args: str) -> tuple[str, list]:
        assert self.selected is not None
        box = self.server.folders[self.selected]
        command = command.upper()
        self.server.commands.append(" ".join(["UID", command, *[str(a) for a in args]]))
        if command == "SEARCH":
            return "OK", [b" ".join(str(uid).encode() for uid in sorted(box))]
        uid = int(args[0])
        if command == "FETCH":
            raw = box[uid]
            if args[1] == "(RFC822.SIZE)":
                return "OK", [f"1 (UID {uid} RFC822.SIZE {len(raw)})".encode()]
            assert args[1] == "(BODY.PEEK[])"  # never plain BODY[]: that would mark it read
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        if command == "MOVE":
            assert "MOVE" in self.server.capabilities
            self.server.folders[self._name(args[1])][uid] = box.pop(uid)
            return "OK", [None]
        if command == "COPY":
            self.server.folders[self._name(args[1])][uid] = box[uid]
            return "OK", [None]
        if command == "STORE":
            assert args[1:] == ("+FLAGS.SILENT", r"(\Deleted)")
            self.server.deleted.add((self.selected, uid))
            return "OK", [None]
        if command == "EXPUNGE":
            assert "UIDPLUS" in self.server.capabilities
            self._expunge({uid})
            return "OK", [None]
        raise AssertionError(f"unexpected UID {command}")

    def _expunge(self, only: set[int] | None = None) -> None:
        assert self.selected is not None
        for folder, uid in list(self.server.deleted):
            if folder == self.selected and (only is None or uid in only):
                self.server.folders[folder].pop(uid, None)
                self.server.deleted.discard((folder, uid))

    def expunge(self) -> tuple[str, list]:
        self.server.commands.append("EXPUNGE")
        self._expunge()
        return "OK", [None]

    def logout(self) -> tuple[str, list]:
        self.calls.append("logout")
        return "BYE", [b""]


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    FakeIMAP.instances = []
    FakeIMAP.server = FakeServer()
    monkeypatch.setattr(imap_poller.imaplib, "IMAP4", FakeIMAP)
    monkeypatch.setattr(imap_poller.imaplib, "IMAP4_SSL", FakeIMAP)
    return FakeIMAP.server


@pytest.fixture
def settings(make_settings):
    return make_settings(imap_host="greenmail", imap_password="pw", poll_interval_seconds=5)


@pytest.fixture
def queued() -> list[object]:
    return []


@pytest.fixture
def intake(session_factory, store, queued) -> Intake:
    return Intake(sessionmaker=session_factory, store=store, enqueue=queued.append)


def mailbox_reports(session_factory) -> list[Report]:
    with session_factory() as session:
        return list(session.scalars(select(Report).order_by(Report.received_at)))


# --------------------------------------------------------------------------- Message-ID


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"Message-ID: <a@example.edu>\r\n\r\nbody", "<a@example.edu>"),
        (b"message-id:\r\n  <folded@example.edu>\r\nX: y\r\n\r\n", "<folded@example.edu>"),
        (b"Subject: x\n\nMessage-ID: <in-body@example.edu>\n", None),  # body, not header
        (b"Message-ID: no-brackets@example.edu\r\n\r\n", None),
        (b"Message-ID: <two words@example.edu>\r\n\r\n", None),
        (b"Subject: x\r\n\r\n", None),
    ],
)
def test_message_id(raw: bytes, expected: str | None) -> None:
    assert message_id(raw) == expected


# --------------------------------------------------------------------------- polling


def test_poll_stores_queues_and_moves(
    server: FakeServer, settings, intake: Intake, queued, session_factory, store, tmp_path: Path
) -> None:
    server.deliver(raw_message(1), raw_message(2))
    beat = tmp_path / "hb"
    result = imap_poller.poll_once(settings, intake, beat)
    assert (result.queued, result.duplicates, result.rejected) == (2, 0, 0)
    assert server.folders["INBOX"] == {}
    assert sorted(server.folders["Processed"]) == [1, 2]
    assert "Rejected" in server.folders
    assert beat.exists()

    reports = mailbox_reports(session_factory)
    assert [r.outer_message_id for r in reports] == [
        "<report-1@example.edu>",
        "<report-2@example.edu>",
    ]
    assert all(r.source is ReportSource.IMAP and r.status is ReportStatus.QUEUED for r in reports)
    assert all(r.reporter_email is None for r in reports)  # the worker reads the From header
    assert queued == [r.id for r in reports]
    assert result.report_ids == [str(r.id) for r in reports]
    assert store.read(reports[0].submission_path) == raw_message(1)  # stored byte for byte

    conn = FakeIMAP.instances[0]
    assert conn.calls[0] == "login report-phishing@example.edu pw"
    assert conn.calls[-1] == "logout"
    assert conn.kwargs["timeout"] == imap_poller.IMAP_TIMEOUT_SECONDS
    assert 'UID MOVE 1 "Processed"' in server.commands


def test_a_message_seen_again_is_not_a_second_report(
    server: FakeServer, settings, intake: Intake, queued, session_factory, tmp_path: Path
) -> None:
    server.deliver(raw_message(1))
    imap_poller.poll_once(settings, intake, tmp_path / "hb")
    # The poller crashed before the move, or someone dragged it back to the inbox.
    server.deliver(raw_message(1))
    result = imap_poller.poll_once(settings, intake, tmp_path / "hb")
    assert (result.queued, result.duplicates) == (0, 1)
    assert len(mailbox_reports(session_factory)) == 1
    assert len(queued) == 1
    assert server.folders["INBOX"] == {}


def test_without_message_id_duplicates_are_found_by_hash(
    server: FakeServer, settings, intake: Intake, session_factory, tmp_path: Path
) -> None:
    server.deliver(raw_message(7, with_id=False), raw_message(7, with_id=False))
    result = imap_poller.poll_once(settings, intake, tmp_path / "hb")
    assert (result.queued, result.duplicates) == (1, 1)
    [report] = mailbox_reports(session_factory)
    assert report.outer_message_id is None


def test_oversized_message_goes_to_rejected_unread(
    server: FakeServer, settings, intake: Intake, session_factory, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(imap_poller, "MAX_MESSAGE_BYTES", 100)
    server.deliver(raw_message(1) + b"x" * 200, raw_message(2)[:99])
    result = imap_poller.poll_once(settings, intake, tmp_path / "hb")
    assert (result.queued, result.rejected) == (1, 1)
    assert list(server.folders["Rejected"]) == [1]
    assert not any(c.startswith("UID FETCH 1 (BODY") for c in server.commands)  # never downloaded


@pytest.mark.parametrize("uidplus", [True, False])
def test_servers_without_move(
    server: FakeServer, settings, intake: Intake, tmp_path: Path, uidplus: bool
) -> None:
    server.capabilities = ("IMAP4REV1", "UIDPLUS") if uidplus else ("IMAP4REV1",)
    server.deliver(raw_message(1), raw_message(2))
    imap_poller.poll_once(settings, intake, tmp_path / "hb")
    assert server.folders["INBOX"] == {}
    assert sorted(server.folders["Processed"]) == [1, 2]
    assert ("UID EXPUNGE 1" in server.commands) is uidplus
    assert ("EXPUNGE" in server.commands) is not uidplus


def test_at_most_50_messages_per_round(
    server: FakeServer, settings, intake: Intake, tmp_path: Path
) -> None:
    server.deliver(*(raw_message(n) for n in range(60)))
    assert imap_poller.poll_once(settings, intake, tmp_path / "hb").queued == 50
    assert len(server.folders["INBOX"]) == 10


def test_queue_down_stops_the_round(
    server: FakeServer, settings, session_factory, store, tmp_path: Path
) -> None:
    def broken(_report_id: object) -> None:
        raise QueueUnavailable("connection refused")

    intake = Intake(sessionmaker=session_factory, store=store, enqueue=broken)
    server.deliver(raw_message(1), raw_message(2))
    with pytest.raises(QueueUnavailable):
        imap_poller.poll_once(settings, intake, tmp_path / "hb")
    [report] = mailbox_reports(session_factory)
    assert report.status is ReportStatus.FAILED  # kept; `app.cli requeue --failed` retries
    assert list(server.folders["Processed"]) == [1]
    assert list(server.folders["INBOX"]) == [2]  # waits for the next round
    assert not (tmp_path / "hb").exists()  # an unhealthy poller shows up in compose
    assert FakeIMAP.instances[0].calls[-1] == "logout"


# --------------------------------------------------------------------------- connection


def test_tls_connection_verifies_certificates(
    server: FakeServer, make_settings, intake: Intake, tmp_path: Path
) -> None:
    imap_poller.poll_once(make_settings(imap_ssl=True, imap_port=993), intake, tmp_path / "hb")
    context = FakeIMAP.instances[0].kwargs["ssl_context"]
    assert context.verify_mode.name == "CERT_REQUIRED"
    assert context.check_hostname


def test_logout_even_when_login_fails(
    server: FakeServer, settings, intake: Intake, monkeypatch, tmp_path: Path
) -> None:
    original_init = FakeIMAP.__init__

    def failing_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.login_error = imaplib.IMAP4.error("authentication failed")

    monkeypatch.setattr(FakeIMAP, "__init__", failing_init)
    with pytest.raises(imaplib.IMAP4.error):
        imap_poller.poll_once(settings, intake, tmp_path / "hb")
    assert FakeIMAP.instances[0].calls[-1] == "logout"
    assert not (tmp_path / "hb").exists()


def test_missing_inbox(server: FakeServer, make_settings, intake: Intake, tmp_path: Path) -> None:
    settings = make_settings(imap_mailbox="Reports")
    with pytest.raises(imap_poller.MailboxError, match="SELECT Reports"):
        imap_poller.poll_once(settings, intake, tmp_path / "hb")


def test_run_survives_errors_and_stops(
    settings, intake: Intake, tmp_path: Path, monkeypatch
) -> None:
    stop = threading.Event()
    calls = []

    def flaky(_settings, _intake, _heartbeat):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("connection refused")
        stop.set()
        return imap_poller.PollResult()

    monkeypatch.setattr(stop, "wait", lambda _timeout: stop.is_set())
    imap_poller.run(settings, stop, tmp_path / "hb", intake=intake, poll=flaky)
    assert len(calls) == 2


def test_default_intake_is_built_from_settings(settings, monkeypatch) -> None:
    import app.db.session

    monkeypatch.setattr(app.db.session, "get_sessionmaker", lambda: "sessionmaker")
    intake = imap_poller.default_intake(settings)
    assert intake.sessionmaker == "sessionmaker"
    assert intake.store.root == settings.storage_dir
