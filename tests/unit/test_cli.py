from __future__ import annotations

import io

import pytest
from pydantic import ValidationError

from app import cli
from app.config import ConfigError


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "postgresql+psycopg://user:s3cret@db:5432/app",
            "postgresql+psycopg://user:***@db:5432/app",
        ),
        ("redis://:s3cret@cache:6379/0", "redis://:***@cache:6379/0"),
        ("redis://cache:6379/0", "redis://cache:6379/0"),
        ("postgresql://user@db/app", "postgresql://user@db/app"),
    ],
)
def test_redact_url(url: str, expected: str) -> None:
    assert cli.redact_url(url) == expected


def test_check_config_masks_secrets(monkeypatch: pytest.MonkeyPatch, make_settings) -> None:
    settings = make_settings(
        database_url="postgresql+psycopg://pt:db-password@db:5432/pt",
        vt_api_key="vt-key-123",
        imap_password="mailbox-password",
    )
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    out = io.StringIO()
    assert cli.main(["check-config"], out=out) == 0
    text = out.getvalue()
    assert "db-password" not in text
    assert "vt-key-123" not in text
    assert "mailbox-password" not in text
    assert "virustotal:    configured" in text
    assert "urlhaus:       not set" in text
    assert "example.edu" in text


@pytest.mark.parametrize("error", [ConfigError("bad policy"), None])
def test_check_config_reports_errors(monkeypatch: pytest.MonkeyPatch, capsys, error) -> None:
    def broken():
        if error is not None:
            raise error
        from app.config import Policy

        Policy.model_validate({"org_domains": []})  # raises ValidationError

    monkeypatch.setattr(cli, "get_settings", broken)
    assert cli.main(["check-config"], out=io.StringIO()) == 2
    assert "configuration error" in capsys.readouterr().err


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "PhishTriage" in capsys.readouterr().out


def test_validation_error_type_is_handled() -> None:
    assert issubclass(ValidationError, ValueError)
