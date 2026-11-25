# PhishTriage

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

A self-hosted platform for **suspicious-email reports**: employees forward a suspicious email
as an attachment, PhishTriage parses and analyses it, looks up threat intelligence, scores it
with explainable rules, replies to the reporter with a verdict, and gives SOC analysts a web
console to review, re-classify and export IOCs.

> **Status:** v1.0.0. Every item of the MVP scope is done; how it was built, milestone by
> milestone, and every design decision are in [PROGRESS.md](PROGRESS.md).

## Demo

![An employee reports an email, gets the verdict by email, and the analyst sees the evidence](docs/images/demo.gif)

_An employee reports a phishing email by email; within seconds PhishTriage replies with
the verdict and its reasons, and the analyst console shows every rule with its evidence.
All data is synthetic._

## Why

A university SOC receives a steady stream of "is this phishing?" reports. Triage by hand is
slow and inconsistent: one analyst checks the headers, another only the links, and the
reporter waits hours for an answer. PhishTriage does the repetitive first pass in seconds,
the same way every time, and shows its evidence so an analyst can confirm or overrule it.

## Features

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
- Data retention: raw emails and attachments are deleted after 90 days; verdicts and IOCs
  stay.
- One-command demo with synthetic data, and an evaluation script for labelled mail sets.

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
| `worker` | RQ worker: parse → analyse → threat intel → score → reply; the daily retention purge. |
| `poller` | Polls the IMAP report mailbox every 30 s and queues new reports. |
| `db` / `redis` | PostgreSQL 16 for reports and evidence; Redis 7 for the queue, cache, rate limits and sessions. |
| `greenmail` / `mailpit` | Local report mailbox and reply catcher, for development and the demo only. |

How a report travels through these processes, the data model and the retention job:
[docs/architecture.md](docs/architecture.md).

## How scoring works

Five analyzers raise rules with fixed IDs; each rule has points and evidence (the field
examined, its value and what matched). Points are added up, once per rule, and the total
maps to a verdict. Full rule table and details: [docs/scoring.md](docs/scoring.md).

| Verdict | Condition | Example rules |
| --- | --- | --- |
| Malicious | ≥ 70, or any `*_INTEL_MALICIOUS` | `ATT_EXECUTABLE` 40, `SENDER_LOOKALIKE_DOMAIN` 30 |
| Suspicious | 40–69 | `AUTH_DMARC_FAIL` 30, `URL_CREDENTIAL_FORM` 25 |
| Low risk | 15–39 | `URL_IP_HOST` 15, `CONTENT_CREDENTIAL_REQUEST` 15 |
| No issues found | < 15 | `URL_SHORTENER` 5, `CONTENT_URGENCY` 5 |

Points live in `app/scoring/rules.yaml`, so tuning never needs a code change. Replies never
call an email "safe".

## Threat intelligence

The worker looks up attachment hashes and URLs on VirusTotal, URLs and hosts on URLhaus,
and the sender domain's registration date over RDAP, then runs the rules on those answers.
Keys are optional: without them the lookups are recorded as `skipped` and everything else
works. Answers are cached in Redis (VirusTotal 24 h, URLhaus 1 h), and VirusTotal is held
to its free-tier limits by a token bucket shared by all workers (at most 4 requests in any
60 seconds, proven with a fake clock in the tests) and a daily budget of 500. Details,
statuses and settings: [docs/intel.md](docs/intel.md).

## Analyst console

Analysts log in (accounts are created with `python -m app.cli create-user`) and work
through a queue they can filter by verdict, status and review state. A report's page shows
the verdict with every matched rule and its evidence, the defanged indicators with their
threat-intel answers, attachments, Authentication-Results, the Received chain, the plain
text body and, inside a sandboxed frame, the sanitised HTML body. Analysts can set their
own verdict (the automatic score is kept), add notes, re-run the analysis, download
attachments as ZIPs encrypted with the password `infected`, and export indicators as CSV
or as a STIX 2.1 bundle. Logins, verdict changes, notes, downloads and exports are written
to an audit log that administrators can browse. A statistics page shows reported emails
per week, the verdict distribution, the time to verdict and how often analysts disagreed
with the rules. Details: [docs/console.md](docs/console.md).

## Report mailbox and replies

Employees forward a suspicious email, as an attachment, to the report mailbox. The poller
fetches new messages over IMAP (reading them without marking them as read), skips any it
has seen before by Message-ID, queues them and moves them to a `Processed` folder. Once the
worker has a verdict it replies to the reporter in plain text: the verdict, what to do,
and the main reasons. The reply goes only to addresses in the organisation's own domains,
and only if the organisation's mail server recorded a DMARC pass for the report, so
nobody can make PhishTriage mail a third party; each reporter gets at most 20 replies an
hour. An inline forward is analysed too, and its reply asks for "Forward as attachment"
next time. Details: [docs/mailbox.md](docs/mailbox.md).

## Security design

Every reported email is treated as attacker-controlled input. Highlights (the full STRIDE
model, with the code and test behind each control, is in
[docs/threat-model.md](docs/threat-model.md)):

- The server never visits links from emails and never renders their original HTML.
- Attachments are never executed or uploaded anywhere; only their hashes are looked up.
  URLs are looked up, never submitted for scanning.
- The web process never parses email; the worker does. Its HTTP client can only reach the
  fixed intel hosts (no redirects, HTTPS only), so email content cannot make it fetch
  anything else.
- Archives are listed, never extracted; strict size and nesting limits.
- Verdict replies go only to the organisation's own, DMARC-verified reporters (at most 20
  an hour each), are plain text from a fixed template, and carry the reported subject
  only defanged, so the platform cannot be used to send spam or links to anyone.
- Console: argon2id passwords, server-side sessions with HttpOnly/SameSite cookies, CSRF
  tokens on every form, account lock after 5 failed logins in 15 minutes, a strict CSP
  without inline script, and every attacker-controlled string rendered escaped.
- Secrets come only from environment variables; the policy file rejects unknown keys.
- Raw emails, attachments and bodies are deleted after 90 days (configurable).
- CI runs ruff, mypy, the tests on SQLite and PostgreSQL, pip-audit, gitleaks, a Trivy
  image scan and an end-to-end mail test against the Compose stack.
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
docker compose exec web python -m app.cli create-user admin@example.edu --role admin
```

The last command asks for a password (12+ characters) for the first console account.

| URL | What |
| --- | --- |
| http://localhost:8000 | PhishTriage analyst console (log in with that account) |
| http://localhost:8025 | Mailpit: replies sent by PhishTriage |

Try it with one of the synthetic sample emails:

- Email, the way employees report: send every sample in `samples/` to the report mailbox
  (GreenMail) and wait for PhishTriage's replies, which land in Mailpit:

  ```bash
  python3 scripts/send_sample.py --wait 90
  # sent credential-phish.eml as <...@example.edu>
  # ...
  # reply for credential-phish.eml: [PhishTriage] Malicious: Action required: verify your account
  ```

  Open http://localhost:8025 to read the replies and http://localhost:8000/reports to see
  the reports. `--from outsider@external.example` shows that an external reporter gets
  no reply.
- A history for the queue and the statistics page: `docker compose run --rm seed` runs
  150 sample submissions through the real analysis, spread over the last 12 weeks, with
  some review work by a demo analyst (`scripts/seed_demo.py`; no replies are sent).
- Upload: log in, open http://localhost:8000/upload and choose a file from
  `tests/fixtures/emails/`. The report page waits for the worker and shows the verdict,
  its evidence and the intel; the queue at http://localhost:8000/reports lists them all.
- REST API: set `API_TOKEN` in `.env` (32+ characters), restart, then submit and wait for
  the verdict (the script polls `GET /api/reports/{id}` until the worker is done):

  ```bash
  API_TOKEN=... python3 scripts/submit_report.py \
      tests/fixtures/emails/02_html_link_mismatch_b64.eml
  ```

  The API itself answers `202 Accepted` with the report ID; analysis runs in the worker.

- Command line, without any server or network: `uv run python -m app.cli analyze
  tests/fixtures/emails/06_report_with_attached_original.eml --wrapper` prints JSON.
- Threat intel: put `VT_API_KEY` and/or `URLHAUS_AUTH_KEY` in `.env` and restart the
  worker (`docker compose up -d worker`). Demo samples use reserved domains, so their
  lookups come back "not found"; that is expected.

### Development

```bash
uv sync                     # Python 3.12 + all dependencies from uv.lock
uv run pre-commit install   # ruff, mypy, gitleaks on every commit
uv run pytest               # tests never touch the network (respx blocks it)
uv run pytest -m live tests/live   # opt-in: real provider lookups, needs your keys
# opt-in end to end against `API_TOKEN=... docker compose up` (see docs/mailbox.md):
PHISHTRIAGE_BASE_URL=http://127.0.0.1:8000 PHISHTRIAGE_API_TOKEN=... uv run pytest -m integration tests/integration
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

`scripts/evaluate.py` runs the rules offline on labelled mail and reports precision,
recall, false-positive rate, the confusion matrix, a threshold sweep and per-rule hit
rates. "Positive" is malicious or suspicious; the targets are recall ≥ 90 % and a
false-positive rate ≤ 5 %.

| Data | Emails | Precision | Recall | False-positive rate |
| --- | --- | --- | --- | --- |
| Synthetic samples (`tests/fixtures/emails/`) | 10 phishing, 5 legitimate | 100 % | 100 % | 0 % |
| Original full-corpus baseline (default policy, offline) | 101 phishing, 2,750 legitimate | 6.25% | 2.97% | 1.64% |
| Tuned dev split (default policy, offline) | 58 phishing, 1,395 legitimate | 72.00% | 31.03% | 0.50% |
| Tuned held-out split (default policy, offline) | 43 phishing, 1,355 legitimate | 53.85% | 16.28% | 0.44% |
| Extra held-out Nazario 2025 | 481 phishing, no ham | N/A | 15.18% | N/A |

The synthetic samples were written with the rules, so their 100 % is a regression test,
not an estimate of real-world accuracy. The method, the commands for the public corpora
and measured results are in [docs/evaluation.md](docs/evaluation.md).

**The recall target remains unmet.** On the untouched 2021 held-out split, detection
improved from 2/43 to 7/43 and false alarms fell from 23/1,355 to 6/1,355. On the
later 2025 corpus, detection improved from 8/481 to 73/481; no contemporary ham was
available to estimate its precision or FPR. Weights were selected only on dev, then
frozen before held-out evaluation. These local historical measurements do not establish
production accuracy. See [the dated report and aggregate results](docs/evaluation.md#detection-tuning--2026-11-25)
for provenance, limitations, the separate authentication experiment and reproduction.

## Limitations and roadmap

- No dynamic sandbox: links are never opened and attachments never run.
- No mailbox-wide purge of similar messages (needs mail-admin rights).
- Development and the demo use local mail servers, not a real Microsoft 365 or Google
  Workspace tenant.
- The free VirusTotal API (4 requests/min, 500/day) is for non-commercial use only; a real
  deployment at an institution needs a paid licence.
- The reply rule trusts the DMARC result that the organisation's mail server writes, so
  that server must strip forged `Authentication-Results` headers (see
  [docs/mailbox.md](docs/mailbox.md)).
- No two-factor authentication for the console yet.

Possible next steps: grouping reports into campaigns ("12 people reported this"), a
report button for Outlook or Gmail, OAuth2 access to a Microsoft 365 or Gmail test
mailbox, landing-page screenshots through urlscan.io private scans, pushing confirmed
IOCs to MISP, YARA rules for attachments, and Slack or Teams alerts for malicious
verdicts.

## License

[MIT](LICENSE)
