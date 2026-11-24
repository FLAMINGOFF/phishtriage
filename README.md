# PhishTriage

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

A self-hosted platform for **suspicious-email reports**: employees forward a suspicious email
as an attachment, PhishTriage parses and analyses it, looks up threat intelligence, scores it
with explainable rules, replies to the reporter with a verdict, and gives SOC analysts a web
console to review, re-classify and export IOCs.

> **Status:** under active development. Done: M0 (skeleton), M1 (parsing and IOC
> extraction). See [PROGRESS.md](PROGRESS.md).

## Demo

_A GIF of "report → reply → analyst view" is added in M6._

## Why

A university SOC receives a steady stream of "is this phishing?" reports. Triage by hand is
slow and inconsistent: one analyst checks the headers, another only the links, and the
reporter waits hours for an answer. PhishTriage does the repetitive first pass in seconds,
the same way every time, and shows its evidence so an analyst can confirm or overrule it.

## Features

Planned for v1.0 (see [PROGRESS.md](PROGRESS.md) for what is done):

- Three intake channels: an IMAP report mailbox, `.eml` upload in the web console, and a REST
  API (`POST /api/reports`).
- Robust parsing of the reported message, including originals attached as `message/rfc822`,
  inline forwards, odd charsets and malformed headers.
- Five analyzers (authentication, sender, links, attachments, content) and threat-intel
  lookups (VirusTotal, URLhaus, RDAP) with caching and rate limits.
- Explainable scoring: every verdict lists rule IDs, points and evidence.
- Automatic verdict replies to internal reporters, with anti-abuse limits.
- Analyst console: queue, detail view, re-classification, notes, audit log, IOC export
  (CSV, STIX 2.1) and statistics.

## Architecture

```mermaid
flowchart LR
    subgraph intake[Intake]
        mailbox[(Report mailbox<br/>IMAP)] --> poller
        upload[.eml upload] --> web
        api[POST /api/reports] --> web
    end
    poller -->|report ID| queue[(Redis queue)]
    web -->|report ID| queue
    queue --> worker
    worker -->|parse · analyse · score| db[(PostgreSQL)]
    worker -->|hash and URL lookups only| intel[VirusTotal · URLhaus · RDAP]
    worker -->|verdict reply| smtp[SMTP to reporter]
    analyst((Analyst)) --> web
    web -->|read| db
```

| Process | Role |
| --- | --- |
| `web` | FastAPI: analyst console, `.eml` upload, REST API, login. Never parses email. |
| `worker` | RQ worker: parse → analyse → threat intel → score → reply. |
| `poller` | Polls the IMAP report mailbox every 30 s and queues new reports. |
| `db` / `redis` | PostgreSQL 16 for reports and evidence; Redis 7 for the queue, cache and rate limits. |
| `greenmail` / `mailpit` | Local report mailbox and reply catcher, for development and the demo only. |

## How scoring works

_Documented in M2 (`docs/scoring.md`)._ In short: each rule has a fixed ID, points and
evidence; the total maps to *Malicious* (≥ 70 or any threat-intel hit), *Suspicious*
(40–69), *Low risk* (15–39) or *No issues found* (< 15). Replies never call an email "safe".

## Security design

Every reported email is treated as attacker-controlled input. Highlights (full STRIDE model
in `docs/threat-model.md`, M6):

- The server never visits links from emails and never renders their original HTML.
- Attachments are never executed or uploaded anywhere; only their hashes are looked up.
- Archives are listed, never extracted; strict size and nesting limits.
- Secrets come only from environment variables; the policy file rejects unknown keys.
- Containers run as an unprivileged user with a read-only root filesystem and no Linux
  capabilities; demo ports are bound to `127.0.0.1`.

## Quick start

Requirements: Docker with Compose v2.

```bash
git clone https://github.com/FLAMINGOFF/phishtriage.git
cd phishtriage
cp .env.example .env          # optional for the demo; needed for API keys
docker compose up --build --wait
curl http://localhost:8000/healthz   # {"status":"ok"}
curl http://localhost:8000/readyz    # database and Redis checks
```

| URL | What |
| --- | --- |
| http://localhost:8000 | PhishTriage web (analyst console from M4) |
| http://localhost:8025 | Mailpit: replies sent by PhishTriage |

Try the parser on one of the synthetic sample emails:

- Upload: open http://localhost:8000/upload and choose a file from `tests/fixtures/emails/`.
- REST API: set `API_TOKEN` in `.env` (32+ characters), restart, then

  ```bash
  curl -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: message/rfc822" \
       --data-binary @tests/fixtures/emails/02_html_link_mismatch_b64.eml \
       http://localhost:8000/api/reports
  ```

- Command line, without any server: `uv run python -m app.cli analyze
  tests/fixtures/emails/06_report_with_attached_original.eml --wrapper` prints JSON.

Sending a sample report by email (`scripts/send_sample.py`) arrives in M5.

### Development

```bash
uv sync                     # Python 3.12 + all dependencies from uv.lock
uv run pre-commit install   # ruff, mypy, gitleaks on every commit
uv run pytest               # tests never touch the network
uv run ruff check . && uv run ruff format --check . && uv run mypy app
uv run python -m app.cli check-config
uv run python scripts/generate_emails.py           # regenerate the sample emails
UPDATE_SNAPSHOTS=1 uv run pytest tests/unit/test_snapshots.py   # after a parser change
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/test uv run pytest  # PostgreSQL
```

The 14 sample emails in `tests/fixtures/emails/` are generated by
`scripts/generate_emails.py` and use only reserved domains (`example.com`, `example.edu`,
`.example`, `.test`). They cover quoted-printable and base64 bodies, GBK and ISO-2022-JP,
malformed headers, originals attached as `message/rfc822` or as `.eml` files, inline
forwards, look-alike and punycode domains, numeric IP hosts, shorteners, double file
extensions, a right-to-left override in a file name and forged authentication headers.

## Evaluation

_Precision and recall on a labelled dataset are reported in M6 (`docs/evaluation.md`)._

## Limitations and roadmap

- No dynamic sandbox: links are never opened and attachments never run.
- No mailbox-wide purge of similar messages (needs mail-admin rights).
- Development and the demo use local mail servers, not a real Microsoft 365 or Google
  Workspace tenant.
- The free VirusTotal API (4 requests/min, 500/day) is for non-commercial use only; a real
  deployment at an institution needs a paid licence.

## License

[MIT](LICENSE)
