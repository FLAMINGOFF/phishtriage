"""Command line: ``python -m app.cli <command>``.

Commands so far:

* ``check-config``: validate settings and policy and print a summary with secrets masked.
  Handy as ``docker compose run --rm web python -m app.cli check-config``.

``analyze`` (M1) and ``create-user`` (M4) follow.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from app import __version__
from app.config import ConfigError, Settings, get_settings


def redact_url(url: str) -> str:
    """Mask the password in a URL such as ``postgresql://user:pw@host/db``."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    userinfo = f"{parts.username}:***" if parts.username else ":***"
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urlunsplit(parts._replace(netloc=f"{userinfo}@{host}"))


def _configured(value: object) -> str:
    return "configured" if value else "not set (lookups skipped)"


def describe(settings: Settings) -> list[str]:
    policy = settings.policy
    return [
        f"PhishTriage {__version__} ({settings.app_env})",
        f"database:      {redact_url(settings.database_url)}",
        f"redis:         {redact_url(settings.redis_url)}",
        f"imap:          {settings.imap_user} @ {settings.imap_host}:{settings.imap_port}"
        f" ({'TLS' if settings.imap_ssl else 'plain'})",
        f"virustotal:    {_configured(settings.vt_api_key)}",
        f"urlhaus:       {_configured(settings.urlhaus_auth_key)}",
        f"org domains:   {', '.join(policy.org_domains)}",
        f"trusted authserv-ids: {', '.join(policy.trusted_authserv_ids) or '(none)'}",
        f"protected:     {len(policy.protected_domains)} domain(s), "
        f"{len(policy.protected_names)} name(s)",
    ]


def cmd_check_config(_args: argparse.Namespace, out: TextIO) -> int:
    try:
        settings = get_settings()
    except (ConfigError, ValidationError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    for line in describe(settings):
        print(line, file=out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="PhishTriage CLI")
    parser.add_argument("--version", action="version", version=f"PhishTriage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-config", help="validate configuration and print a summary")
    check.set_defaults(handler=cmd_check_config)
    return parser


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args, out))


if __name__ == "__main__":
    sys.exit(main())
