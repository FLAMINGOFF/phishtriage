from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app import healthcheck


@dataclass
class FakeWorker:
    hostname: str | None
    last_heartbeat: datetime | None


def workers_of(*items: FakeWorker):
    return lambda _conn: list(items)


class TestWorkerCheck:
    def test_fresh_worker_on_this_host(self) -> None:
        beat = datetime.now(UTC) - timedelta(seconds=10)
        assert healthcheck.check_worker(
            None, "abc123", 480, workers=workers_of(FakeWorker("abc123", beat))
        )

    def test_worker_on_other_host_does_not_count(self) -> None:
        beat = datetime.now(UTC)
        assert not healthcheck.check_worker(
            None, "abc123", 480, workers=workers_of(FakeWorker("other", beat))
        )

    def test_stale_heartbeat(self) -> None:
        beat = datetime.now(UTC) - timedelta(minutes=30)
        assert not healthcheck.check_worker(
            None, "abc123", 480, workers=workers_of(FakeWorker("abc123", beat))
        )

    def test_no_heartbeat_or_no_workers(self) -> None:
        assert not healthcheck.check_worker(
            None, "abc123", 480, workers=workers_of(FakeWorker("abc123", None))
        )
        assert not healthcheck.check_worker(None, "abc123", 480, workers=workers_of())


class TestPollerCheck:
    def test_fresh_heartbeat(self, tmp_path: Path) -> None:
        beat = tmp_path / "hb"
        beat.touch()
        assert healthcheck.check_poller(beat, 100)

    def test_stale_heartbeat(self, tmp_path: Path) -> None:
        beat = tmp_path / "hb"
        beat.touch()
        old = beat.stat().st_mtime - 1000
        os.utime(beat, (old, old))
        assert not healthcheck.check_poller(beat, 100)

    def test_missing_heartbeat(self, tmp_path: Path) -> None:
        assert not healthcheck.check_poller(tmp_path / "none", 100)


class FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestWebCheck:
    def test_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            healthcheck.urllib.request, "urlopen", lambda *a, **k: FakeResponse(200)
        )
        assert healthcheck.check_web()

    def test_connection_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*_a, **_k):
            raise ConnectionRefusedError

        monkeypatch.setattr(healthcheck.urllib.request, "urlopen", refuse)
        assert not healthcheck.check_web()

    def test_real_closed_port(self) -> None:
        # Nothing listens on port 9 (discard) on loopback in the test environment.
        assert not healthcheck.check_web("http://127.0.0.1:9/readyz", timeout=0.5)


class TestMain:
    def test_web(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(healthcheck, "check_web", lambda: True)
        assert healthcheck.main(["web"]) == 0
        monkeypatch.setattr(healthcheck, "check_web", lambda: False)
        assert healthcheck.main(["web"]) == 1

    def test_poller(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, make_settings) -> None:
        settings = make_settings(poll_interval_seconds=30)
        monkeypatch.setattr("app.config.get_settings", lambda: settings)
        seen = {}

        def fake_check(path: Path, max_age: float) -> bool:
            seen["max_age"] = max_age
            return True

        monkeypatch.setattr(healthcheck, "check_poller", fake_check)
        assert healthcheck.main(["poller"]) == 0
        assert seen["max_age"] == 3 * 30 + healthcheck.IMAP_TIMEOUT_SECONDS

    def test_worker(self, monkeypatch: pytest.MonkeyPatch, make_settings) -> None:
        settings = make_settings()
        monkeypatch.setattr("app.config.get_settings", lambda: settings)
        monkeypatch.setattr("app.redis_client.get_redis", lambda: None)
        monkeypatch.setattr(healthcheck, "check_worker", lambda *a, **k: False)
        assert healthcheck.main(["worker"]) == 1

    def test_unknown_component(self) -> None:
        with pytest.raises(SystemExit):
            healthcheck.main(["db"])
