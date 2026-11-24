"""Application configuration.

Configuration comes from two places, on purpose:

* **Environment variables** (optionally via a ``.env`` file) hold deployment details and
  secrets: database and Redis URLs, mailbox credentials, API keys. Nothing secret is ever
  read from YAML, so a policy file can be committed and reviewed without leaking anything.
* **config/settings.yaml** holds *policy*: which domains belong to the organisation, which
  names and domains attackers imitate, which mail servers we trust for
  ``Authentication-Results``. Policy changes how verdicts are reached, so it lives in a file
  that is reviewed like code.

Both end up in one immutable :class:`Settings` object (``settings.policy`` is the YAML part).
"""

from __future__ import annotations

import logging
import os
import re
from email.utils import parseaddr
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS_FILE = PROJECT_ROOT / "config" / "settings.yaml"
EXAMPLE_SETTINGS_FILE = PROJECT_ROOT / "config" / "settings.example.yaml"
SETTINGS_FILE_ENV = "PHISHTRIAGE_SETTINGS_FILE"

# Only good enough for a laptop demo. Production refuses to start with it (see Settings).
DEV_SECRET_KEY = "dev-only-insecure-secret-key-change-me"  # noqa: S105
MIN_SECRET_KEY_LENGTH = 32

# One DNS label: letters, digits and inner hyphens, at most 63 characters.
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ConfigError(RuntimeError):
    """The configuration is missing or invalid; the process should not start."""


def normalise_domain(value: str) -> str:
    """Return ``value`` as a lower-case ASCII domain without a trailing dot.

    Internationalised domains must be written in their punycode (``xn--``) form, so that
    every later comparison (lookalike checks, reply eligibility) works on one spelling.
    """
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        raise ValueError(f"invalid domain {value!r}")
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(
            f"invalid domain {value!r}: use a plain hostname such as example.edu "
            "(punycode xn-- form for internationalised names)"
        )
    return domain


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


class Policy(BaseModel):
    """Organisation policy, loaded from settings.yaml.

    ``extra="forbid"`` makes a typo (or an API key pasted into the YAML) a startup error
    instead of a silently ignored setting.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    org_domains: tuple[str, ...] = Field(min_length=1)
    protected_domains: tuple[str, ...] = ()
    protected_names: tuple[str, ...] = ()
    trusted_authserv_ids: tuple[str, ...] = ()
    freemail_domains: tuple[str, ...] = ()
    shortener_domains: tuple[str, ...] = ()

    @field_validator("org_domains", "protected_domains", "freemail_domains", "shortener_domains")
    @classmethod
    def _domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(tuple(normalise_domain(v) for v in values))

    @field_validator("trusted_authserv_ids")
    @classmethod
    def _authserv_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        # RFC 8601 compares authserv-id case-insensitively.
        cleaned = tuple(v.strip().lower() for v in values)
        if any(not v or any(ch.isspace() for ch in v) for v in cleaned):
            raise ValueError("authserv-id values must be non-empty and contain no spaces")
        return _dedupe(cleaned)

    @field_validator("protected_names")
    @classmethod
    def _names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(v.split()) for v in values)
        if any(not v for v in cleaned):
            raise ValueError("protected_names must not contain empty entries")
        return _dedupe(cleaned)


def resolve_settings_file(app_env: str | None = None) -> Path:
    """Pick the policy file to load.

    An explicit ``PHISHTRIAGE_SETTINGS_FILE`` must exist. Without one we use
    ``config/settings.yaml``; if that is missing too, development falls back to the example
    policy (so ``docker compose up`` works on a fresh clone), but production refuses to guess.
    """
    explicit = os.environ.get(SETTINGS_FILE_ENV)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"{SETTINGS_FILE_ENV}={explicit} does not exist")
        return path
    if DEFAULT_SETTINGS_FILE.is_file():
        return DEFAULT_SETTINGS_FILE
    if app_env == "prod":
        raise ConfigError(
            f"{DEFAULT_SETTINGS_FILE} not found; production needs an explicit policy file"
        )
    logger.warning("config/settings.yaml not found, using the example policy (example.edu)")
    return EXAMPLE_SETTINGS_FILE


def load_policy_data(path: Path) -> dict[str, Any]:
    """Read a policy file. ``yaml.safe_load`` only: never construct arbitrary objects."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read policy file {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"policy file {path} must contain a mapping at the top level")
    return data


class PolicyFileSource(PydanticBaseSettingsSource):
    """Settings source that supplies only the ``policy`` field, from settings.yaml.

    Because this source returns nothing but ``{"policy": ...}``, secrets and deployment
    settings cannot come from the YAML file even by mistake.
    """

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        # Required by the abstract base class; __call__ below does all the work.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if "policy" in self.current_state:  # passed explicitly, e.g. in tests
            return {}
        app_env = self.current_state.get("app_env")
        path = resolve_settings_file(str(app_env) if app_env else None)
        return {"policy": load_policy_data(path)}


class Settings(BaseSettings):
    """All runtime configuration. Environment variable names are the upper-case field names."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,  # VT_API_KEY= in .env means "not configured", not "empty key"
        extra="ignore",
        frozen=True,
    )

    app_env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    database_url: str = "postgresql+psycopg://phishtriage:phishtriage@localhost:5432/phishtriage"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: SecretStr = SecretStr(DEV_SECRET_KEY)

    # Report mailbox (GreenMail in the demo). The poller only ever reads from it.
    imap_host: str = "localhost"
    imap_port: int = Field(default=3143, ge=1, le=65535)
    imap_ssl: bool = False
    imap_user: str = "report-phishing@example.edu"
    imap_password: SecretStr = SecretStr("")
    imap_mailbox: str = "INBOX"
    poll_interval_seconds: int = Field(default=30, ge=5, le=3600)
    imap_processed_mailbox: str = "Processed"  # handled messages are moved here
    imap_rejected_mailbox: str = "Rejected"  # messages over the size limit

    # Replies to reporters (Mailpit in the demo).
    replies_enabled: bool = True
    reply_from: str = "PhishTriage <report-phishing@example.edu>"
    reply_hourly_limit: int = Field(default=20, ge=1, le=1000)
    smtp_host: str = "localhost"
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    smtp_security: Literal["none", "starttls", "ssl"] = "none"
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")

    # Raw messages and attachments (a dedicated volume in Docker, never the database).
    storage_dir: Path = PROJECT_ROOT / "data" / "storage"

    # Analyst console sessions. Secure cookies need HTTPS; the local http:// demo turns it
    # off (docker-compose.yml), production refuses to.
    session_cookie_secure: bool = True
    session_idle_minutes: int = Field(default=60, ge=5, le=24 * 60)
    session_max_hours: int = Field(default=12, ge=1, le=7 * 24)

    # Bearer token for POST /api/reports. Unset means the API is disabled.
    api_token: SecretStr | None = None
    # Optional copy of app/scoring/rules.yaml to tune points without rebuilding the image.
    rules_file: Path | None = None

    # Threat-intel keys are optional: without them lookups are skipped, nothing breaks.
    vt_api_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    # VirusTotal's free API: 4 requests/minute, 500/day. A paid licence raises both.
    vt_rate_per_minute: int = Field(default=4, ge=1, le=10_000)
    vt_daily_budget: int = Field(default=500, ge=0)
    # Fresh (uncached) VirusTotal lookups per report: hashes first, then URLs, then domains.
    vt_max_lookups_per_report: int = Field(default=4, ge=0, le=100)
    # How long a lookup may wait for a rate-limit slot before it is skipped.
    intel_max_wait_seconds: float = Field(default=60.0, ge=0, le=600)
    intel_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    # RDAP needs no key; it only contacts the servers listed in app/intel/rdap_bootstrap.json.
    rdap_enabled: bool = True

    policy: Policy

    @field_validator("reply_from")
    @classmethod
    def _reply_from(cls, value: str) -> str:
        _, address = parseaddr(value)
        if "@" not in address or any(ch in value for ch in "\r\n"):
            raise ValueError("REPLY_FROM must look like 'PhishTriage <soc@example.edu>'")
        return value

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        """Fail closed: refuse to run in production with demo-grade settings."""
        if self.app_env != "prod":
            return self
        problems = []
        key = self.secret_key.get_secret_value()
        if key == DEV_SECRET_KEY or len(key) < MIN_SECRET_KEY_LENGTH:
            problems.append(f"SECRET_KEY must be a random value of {MIN_SECRET_KEY_LENGTH}+ chars")
        if not self.imap_ssl:
            problems.append("IMAP_SSL must be true (the mailbox password would travel in clear)")
        if not self.session_cookie_secure:
            problems.append("SESSION_COOKIE_SECURE must be true (serve the console over HTTPS)")
        if self.smtp_user and self.smtp_security == "none":
            problems.append("SMTP_SECURITY must be starttls or ssl when SMTP_USER is set")
        token = self.api_token.get_secret_value() if self.api_token else None
        if token is not None and len(token) < MIN_SECRET_KEY_LENGTH:
            problems.append(f"API_TOKEN must be {MIN_SECRET_KEY_LENGTH}+ random characters")
        if problems:
            raise ValueError("unsafe production configuration: " + "; ".join(problems))
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Highest priority first. The policy source runs last so it can see APP_ENV.
        return init_settings, env_settings, dotenv_settings, PolicyFileSource(settings_cls)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings, read once. Tests call ``get_settings.cache_clear()``."""
    return Settings()
