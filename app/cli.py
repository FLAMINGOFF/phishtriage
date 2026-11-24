"""Command line: ``python -m app.cli <command>``.

Commands:

* ``analyze FILE.eml``: parse a message offline (no database, no network) and print
  the result as JSON. ``--wrapper`` treats it as a report from the report mailbox.
* ``check-config``: validate settings and policy and print a summary with secrets masked.
  Handy as ``docker compose run --rm web python -m app.cli check-config``.
* ``requeue [ID ...] [--failed] [--stuck-minutes N]``: hand reports to the worker again,
  e.g. after Redis was down when they arrived.
* ``create-user EMAIL [--role analyst|admin] [--password-stdin] [--update]``: create a
  console account (or, with ``--update``, change its password and role). The password
  is asked twice without echo, or read from one line of standard input.

``analyze`` never calls a threat-intel provider; only the worker does.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from app import __version__
from app.analysis import analyze_email
from app.config import ConfigError, Policy, Settings, get_settings
from app.parsing.eml import MessageRejected, ParsedEmail, extract_originals
from app.parsing.iocs import extract_observables


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
        f"virustotal:    {_configured(settings.vt_api_key)}"
        f" ({settings.vt_rate_per_minute}/min, {settings.vt_daily_budget}/day,"
        f" {settings.vt_max_lookups_per_report} per report)",
        f"urlhaus:       {_configured(settings.urlhaus_auth_key)}",
        f"rdap:          {'enabled' if settings.rdap_enabled else 'disabled'}",
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


def summarize_email(parsed: ParsedEmail, policy: Policy) -> dict[str, Any]:
    """JSON-friendly view of one email: verdict and findings first, then the details."""
    analysis = analyze_email(parsed, policy, now=datetime.now(UTC))
    result = analysis.result
    return {
        "verdict": result.verdict.value,
        "score": result.score,
        "findings": [
            {
                "rule_id": f.rule_id,
                "score": f.score,
                "analyzer": f.analyzer,
                "description": f.description,
                "evidence": [e.model_dump() for e in f.evidence],
            }
            for f in result.findings
        ],
        "analysis_errors": analysis.errors,
        "message_id": parsed.message_id,
        "subject": parsed.subject,
        "from": parsed.from_addr.model_dump() if parsed.from_addr else None,
        "reply_to": [a.address for a in parsed.reply_to],
        "return_path": parsed.return_path,
        "sent_at": parsed.sent_at.isoformat() if parsed.sent_at else None,
        "forwarded_inline": parsed.forwarded_inline,
        "received": [
            {"from_host": h.from_host, "from_ip": h.from_ip, "by_host": h.by_host}
            for h in parsed.received
        ],
        "authentication_results": [
            {"authserv_id": a.authserv_id, "results": {r.method: r.result for r in a.results}}
            for a in parsed.authentication_results
        ],
        "body_text_chars": len(parsed.body_text),
        "has_html": parsed.body_html is not None,
        "attachments": [
            {
                "filename": a.filename,
                "declared_type": a.declared_type,
                "detected_type": a.detected_type,
                "size": a.size,
                "sha256": a.sha256,
                "has_macros": a.has_macros,
                "is_encrypted": a.is_encrypted,
            }
            for a in analysis.attachments
        ],
        "observables": [
            o.model_dump() for o in extract_observables(parsed, own_domains=policy.org_domains)
        ],
        "defects": parsed.defects,
    }


def analyze_file(raw: bytes, policy: Policy, *, wrapper: bool) -> dict[str, Any]:
    intake = extract_originals(raw, is_report_wrapper=wrapper)
    return {
        "mode": intake.mode,
        "emails": [summarize_email(original, policy) for original in intake.originals],
    }


def cmd_analyze(args: argparse.Namespace, out: TextIO) -> int:
    try:
        policy = get_settings().policy
    except (ConfigError, ValidationError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        raw = Path(args.file).read_bytes()
    except OSError as exc:
        print(f"cannot read {args.file}: {exc.strerror}", file=sys.stderr)
        return 2
    try:
        result = analyze_file(raw, policy, wrapper=args.wrapper)
    except MessageRejected as exc:
        print(json.dumps({"rejected": exc.reason}), file=out)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False), file=out)
    return 0


def cmd_requeue(args: argparse.Namespace, out: TextIO) -> int:
    from app.db.session import get_sessionmaker
    from app.ingest.submission import requeue_reports
    from app.queueing import QueueUnavailable, rq_enqueuer
    from app.redis_client import redis_client

    try:
        settings = get_settings()
        ids = [uuid.UUID(value) for value in args.report_ids]
    except (ConfigError, ValidationError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except ValueError:
        print("report IDs must be UUIDs", file=sys.stderr)
        return 2
    stuck_before = (
        datetime.now(UTC) - timedelta(minutes=args.stuck_minutes)
        if args.stuck_minutes is not None
        else None
    )
    enqueue = rq_enqueuer(redis_client(settings.redis_url))
    with get_sessionmaker()() as session:
        try:
            queued = requeue_reports(
                session, enqueue, ids, failed=args.failed, stuck_before=stuck_before
            )
        except QueueUnavailable as exc:
            print(f"queue unavailable: {exc}", file=sys.stderr)
            return 1
    print(f"queued {len(queued)} report(s)", file=out)
    for report_id in queued:
        print(report_id, file=out)
    return 0


# Deliberately simple: one "@", no spaces, a dot in the domain. Accounts are created by
# an administrator, so this only catches typos.
_ACCOUNT_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _read_password(from_stdin: bool) -> str | None:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if getpass.getpass("Repeat the password: ") != first:
        print("the passwords do not match", file=sys.stderr)
        return None
    return first


def cmd_create_user(args: argparse.Namespace, out: TextIO) -> int:
    from sqlalchemy import select

    from app.db.models import User, UserRole
    from app.db.session import get_sessionmaker
    from app.web.auth import hash_password, password_problem

    email = args.email.strip().lower()
    if len(email) > 320 or not _ACCOUNT_EMAIL.match(email):
        print(f"not an email address: {args.email!r}", file=sys.stderr)
        return 2
    password = _read_password(args.password_stdin)
    if password is None:
        return 2
    problem = password_problem(password, email)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    try:
        sessionmaker = get_sessionmaker()
    except (ConfigError, ValidationError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    with sessionmaker() as session:
        user = session.scalar(select(User).where(User.email == email))
        if user is not None and not args.update:
            print(f"{email} already exists; use --update to change it", file=sys.stderr)
            return 1
        created = user is None
        if user is None:
            user = User(email=email)
            session.add(user)
        user.password_hash = hash_password(password)
        user.role = UserRole(args.role)
        session.commit()
    print(f"{'created' if created else 'updated'} {args.role} {email}", file=out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="PhishTriage CLI")
    parser.add_argument("--version", action="version", version=f"PhishTriage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="parse an .eml file offline and print JSON")
    analyze.add_argument("file", help="path to the .eml file")
    analyze.add_argument(
        "--wrapper", action="store_true", help="treat it as a report from the report mailbox"
    )
    analyze.set_defaults(handler=cmd_analyze)
    check = sub.add_parser("check-config", help="validate configuration and print a summary")
    check.set_defaults(handler=cmd_check_config)
    requeue = sub.add_parser("requeue", help="hand reports to the worker again")
    requeue.add_argument("report_ids", nargs="*", metavar="ID", help="report IDs")
    requeue.add_argument("--failed", action="store_true", help="all failed reports")
    requeue.add_argument(
        "--stuck-minutes",
        type=int,
        metavar="N",
        help="reports still queued or analysing N minutes after they arrived",
    )
    requeue.set_defaults(handler=cmd_requeue)
    create_user = sub.add_parser("create-user", help="create a console account")
    create_user.add_argument("email", help="the login (email address)")
    create_user.add_argument(
        "--role", choices=["analyst", "admin"], default="analyst", help="default: analyst"
    )
    create_user.add_argument(
        "--password-stdin", action="store_true", help="read the password from standard input"
    )
    create_user.add_argument(
        "--update", action="store_true", help="change the password and role of an existing user"
    )
    create_user.set_defaults(handler=cmd_create_user)
    return parser


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args, out))


if __name__ == "__main__":
    sys.exit(main())
