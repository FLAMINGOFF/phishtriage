# Progress

## Current milestone
M2 – Analyzers and scoring (next)

## Done
- M0 – Skeleton: uv project, ruff/mypy/pytest/pre-commit, settings loader (.env +
  config/settings.yaml), FastAPI `/healthz` and `/readyz`, RQ worker and IMAP poller
  skeletons with real health checks, Alembic, Dockerfile and seven-service Docker Compose
  stack, GitHub Actions (ruff, mypy, pytest, pip-audit, gitleaks, compose smoke test).
- M1 – Email parsing and IOC extraction: `parsing/eml.py` (headers, Received chain,
  Authentication-Results, text/HTML bodies, attachments, `message/rfc822` and `.eml`
  originals, inline-forward detection, size/attachment/nesting limits), charset handling
  (GBK under a gb2312 label, ISO-2022-JP, Big5, unknown charsets), `parsing/iocs.py` and
  `defang.py`, tables `reports`/`emails`/`attachments`/`observables` with a migration,
  content-addressed blob store, `POST /api/reports`, web upload and report page,
  `python -m app.cli analyze`, 14 generated sample emails with JSON snapshots, and a
  mutation test that feeds damaged copies of every sample to the parser.

## Open issues
- None yet

## Decision log
- RQ instead of Celery: simpler, enough for a single node (fixed by the plan).
- Secrets only from environment; `settings.yaml` feeds only the `policy` field and rejects
  unknown keys, so a key pasted into YAML is a startup error.
- Without `config/settings.yaml`, dev falls back to `settings.example.yaml` (zero-config
  demo); `APP_ENV=prod` refuses to fall back and refuses the dev `SECRET_KEY` or plain IMAP.
- `/healthz` is liveness only (no dependencies); `/readyz` checks PostgreSQL and Redis and
  hides error details from the client. Compose health uses `/readyz`.
- Worker health = "this container's RQ worker is registered in Redis with a fresh
  heartbeat"; poller health = "reached the mailbox within 3 poll intervals".
- RQ jobs use the JSON serializer instead of pickle: jobs only carry a report ID, and
  pickle would turn Redis write access into code execution in the worker.
- Web container runs `alembic upgrade head` before serving (single node, no extra one-shot
  service); worker and poller wait for web to be healthy.
- Containers: non-root UID 10001, code owned by root, read-only root filesystem with tmpfs
  `/tmp`, `cap_drop: ALL`, `no-new-privileges`; published ports bound to 127.0.0.1.
- Image tags pinned to exact versions (postgres 16.16, redis 7.4.12, GreenMail 2.1.15,
  Mailpit 1.34.0); Dependabot proposes updates.
- Starlette's TestClient now wants `httpx2`; it is a dev-only dependency. Outbound intel
  calls (M3) use `httpx` + `respx` as the plan specifies.
- CI installs uv with pip at a pinned version instead of a third-party setup action; one
  extra CI job runs `docker compose up --wait` to prove the M0 acceptance criterion.
- README.zh-CN.md added next to the English README (same convention as the author's other
  repositories).
- M1 adds a few modules the plan does not list, to keep `eml.py` readable:
  `parsing/received.py`, `parsing/authres.py` (RFC 8601), `parsing/headertext.py`
  (comment/quote-aware splitting), `parsing/html.py` (link extraction and sanitising),
  `parsing/filetype.py` (libmagic), `app/storage.py` and `ingest/submission.py` (the one
  code path all intake channels share).
- Raw messages and attachments live in a content-addressed blob store
  (`<kind>/<sha256[:2]>/<sha256>`, mode 0640) instead of the database; paths read back
  from the database are validated against that pattern, so a tampered row cannot point
  the server at another file.
- Reserved TLDs (`.example`, `.test`, `.invalid`, `.localhost`) are treated as public
  suffixes, so `login.evil.example` has the registered domain `evil.example` exactly like
  `login.evil.com` would. The demo data relies on this.
- The organisation's own domains (`policy.org_domains`) are not extracted as IOCs: an
  IOC export full of `example.edu` would be noise, and blocking it would be harmful.
- For an inline forward the sender addresses and origin IP belong to the reporter, so they
  are not extracted; only body URLs are (the report is marked `forwarded_inline`).
- An API or upload submission that carries `message/rfc822` attachments is treated as a
  report wrapper too (one report per attached original); one without is analysed directly.
- Malformed input never crashes processing: a message is either parsed (defects are
  recorded) or rejected with a reason (`status=failed`, `error="rejected: ..."`).
  Found by the mutation test and fixed: hostile `From`/`Received` values that crash the
  standard-library header parser, NUL bytes in charset names, and embedded messages the
  standard generator refuses to re-serialise.
- HTML is sanitised with `nh3` using an allow-list without any URL attribute (`href`,
  `src`, `style` are all dropped), so opening the HTML view cannot load a tracking pixel.
  M1 shows only the plain-text body; the sandboxed HTML view arrives with the console.
- File type detection returns "unknown" (not `application/octet-stream`) when libmagic
  is broken, so a bad install cannot make every attachment look harmless. The CI compose
  job checks libmagic inside the image.
- M1 processes submissions synchronously inside the request (as the plan says); M3 moves
  processing to the worker.
- The test suite runs on SQLite and, in CI, again on PostgreSQL 16 (`TEST_DATABASE_URL`);
  a test asserts that the models and the Alembic migrations describe the same schema.

## Manual steps for the user
- Optional: set `API_TOKEN` in `.env` (at least 32 characters) to enable the REST API.
- Optional: create a VirusTotal account and put `VT_API_KEY` in `.env`.
- Optional: request a URLhaus Auth-Key at https://auth.abuse.ch/ and put `URLHAUS_AUTH_KEY` in `.env`.
- GitHub repository settings: add the topics `phishing`, `email-security`, `soc`,
  `threat-intelligence`, `fastapi`.
