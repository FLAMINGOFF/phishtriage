from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from app import config
from app.config import (
    DEV_SECRET_KEY,
    SETTINGS_FILE_ENV,
    ConfigError,
    Policy,
    Settings,
    load_policy_data,
    normalise_domain,
    resolve_settings_file,
)

STRONG_KEY = "k" * 40


def write(tmp_path: Path, text: str, name: str = "settings.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestNormaliseDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Example.EDU", "example.edu"),
            ("  example.edu.  ", "example.edu"),
            ("xn--exmple-cua.edu", "xn--exmple-cua.edu"),
            ("mail.sub.example.com", "mail.sub.example.com"),
        ],
    )
    def test_accepts_and_normalises(self, raw: str, expected: str) -> None:
        assert normalise_domain(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "localhost",
            "user@example.edu",
            "exa mple.edu",
            "-bad.example",
            "ex\u0430mple.edu",
            "http://example.edu",
            "a" * 64 + ".edu",
        ],
    )
    def test_rejects_invalid(self, raw: str) -> None:
        with pytest.raises(ValueError, match="invalid domain"):
            normalise_domain(raw)


class TestPolicy:
    def test_example_policy_is_valid(self, example_policy: Policy) -> None:
        assert example_policy.org_domains == ("example.edu",)
        assert "mx.example.edu" in example_policy.trusted_authserv_ids
        assert "bit.ly" in example_policy.shortener_domains

    def test_values_are_normalised_and_deduplicated(self) -> None:
        policy = Policy(
            org_domains=("Example.edu", "example.edu."),
            trusted_authserv_ids=(" MX.Example.EDU ",),
            protected_names=("  IT   Service Desk ", "IT Service Desk"),
        )
        assert policy.org_domains == ("example.edu",)
        assert policy.trusted_authserv_ids == ("mx.example.edu",)
        assert policy.protected_names == ("IT Service Desk",)

    def test_org_domains_required(self) -> None:
        with pytest.raises(ValidationError):
            Policy(org_domains=())

    def test_unknown_keys_rejected(self) -> None:
        # An API key pasted into the YAML must be an error, not silently accepted.
        with pytest.raises(ValidationError, match="vt_api_key"):
            Policy.model_validate({"org_domains": ["example.edu"], "vt_api_key": "secret"})

    def test_authserv_id_with_space_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Policy(org_domains=("example.edu",), trusted_authserv_ids=("mx example",))

    def test_empty_protected_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Policy(org_domains=("example.edu",), protected_names=("  ",))


class TestPolicyFile:
    def test_safe_load_refuses_python_objects(self, tmp_path: Path) -> None:
        path = write(tmp_path, "org_domains: !!python/object/apply:os.system ['true']\n")
        with pytest.raises(ConfigError, match="cannot read"):
            load_policy_data(path)

    def test_top_level_must_be_mapping(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="mapping"):
            load_policy_data(write(tmp_path, "- example.edu\n"))

    def test_empty_file_is_empty_mapping(self, tmp_path: Path) -> None:
        assert load_policy_data(write(tmp_path, "")) == {}

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_policy_data(tmp_path / "nope.yaml")


class TestResolveSettingsFile:
    def test_explicit_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        path = write(tmp_path, "org_domains: [example.edu]\n")
        monkeypatch.setenv(SETTINGS_FILE_ENV, str(path))
        assert resolve_settings_file() == path

    def test_explicit_path_must_exist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(SETTINGS_FILE_ENV, str(tmp_path / "missing.yaml"))
        with pytest.raises(ConfigError, match="does not exist"):
            resolve_settings_file()

    def test_default_file_preferred(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        default = write(tmp_path, "org_domains: [example.edu]\n")
        monkeypatch.setattr(config, "DEFAULT_SETTINGS_FILE", default)
        assert resolve_settings_file() == default

    def test_dev_falls_back_to_example(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(config, "DEFAULT_SETTINGS_FILE", tmp_path / "absent.yaml")
        with caplog.at_level(logging.WARNING):
            assert resolve_settings_file("dev") == config.EXAMPLE_SETTINGS_FILE
        assert "example policy" in caplog.text

    def test_prod_does_not_fall_back(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(config, "DEFAULT_SETTINGS_FILE", tmp_path / "absent.yaml")
        with pytest.raises(ConfigError, match="production"):
            resolve_settings_file("prod")


class TestSettings:
    def test_defaults(self, make_settings) -> None:
        settings = make_settings()
        assert settings.app_env == "dev"
        assert settings.vt_api_key is None
        assert settings.poll_interval_seconds == 30

    def test_environment_overrides(self, monkeypatch: pytest.MonkeyPatch, make_settings) -> None:
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
        monkeypatch.setenv("POLL_INTERVAL_SECONDS", "60")
        settings = make_settings()
        assert settings.database_url.endswith("@db:5432/x")
        assert settings.poll_interval_seconds == 60

    def test_empty_env_value_means_unset(
        self, monkeypatch: pytest.MonkeyPatch, make_settings
    ) -> None:
        monkeypatch.setenv("VT_API_KEY", "")
        assert make_settings().vt_api_key is None

    def test_policy_loaded_from_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        path = write(
            tmp_path, "org_domains: [uni.example]\ntrusted_authserv_ids: [mx.uni.example]\n"
        )
        monkeypatch.setenv(SETTINGS_FILE_ENV, str(path))
        settings = Settings(_env_file=None)
        assert settings.policy.org_domains == ("uni.example",)

    def test_dotenv_file(self, tmp_path: Path, example_policy) -> None:
        env_file = write(tmp_path, "REDIS_URL=redis://cache:6379/1\n", name=".env")
        settings = Settings(_env_file=env_file, policy=example_policy)
        assert settings.redis_url == "redis://cache:6379/1"

    def test_secrets_masked_in_repr(self, make_settings) -> None:
        settings = make_settings(vt_api_key="vt-secret-value", imap_password="imap-secret")
        text = repr(settings) + str(settings)
        assert "vt-secret-value" not in text
        assert "imap-secret" not in text
        assert settings.vt_api_key.get_secret_value() == "vt-secret-value"

    def test_settings_are_immutable(self, make_settings) -> None:
        settings = make_settings()
        with pytest.raises(ValidationError):
            settings.app_env = "prod"

    def test_poll_interval_bounds(self, make_settings) -> None:
        with pytest.raises(ValidationError):
            make_settings(poll_interval_seconds=1)

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"secret_key": DEV_SECRET_KEY, "imap_ssl": True}, "SECRET_KEY"),
            ({"secret_key": "short", "imap_ssl": True}, "SECRET_KEY"),
            ({"secret_key": STRONG_KEY, "imap_ssl": False}, "IMAP_SSL"),
        ],
    )
    def test_production_guards(self, make_settings, overrides, message) -> None:
        with pytest.raises(ValidationError, match=message):
            make_settings(app_env="prod", **overrides)

    def test_safe_production_config_accepted(self, make_settings) -> None:
        settings = make_settings(app_env="prod", secret_key=STRONG_KEY, imap_ssl=True)
        assert settings.app_env == "prod"

    def test_get_settings_is_cached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)  # no .env here
        monkeypatch.setenv(SETTINGS_FILE_ENV, str(config.EXAMPLE_SETTINGS_FILE))
        first = config.get_settings()
        assert config.get_settings() is first
