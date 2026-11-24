# Progress

## Current milestone
M6 – Hardening, evaluation and presentation (next)

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
- M2 – Analyzers and scoring: five analyzers (auth, sender, urls, attachments, content)
  raising the plan's 23 rules, `app/scoring/rules.yaml` + engine, `findings` table,
  static attachment inspection (libmagic, ZIP listing, oletools), verdict and evidence on
  the report page, in the API and in `python -m app.cli analyze`; every rule has a
  triggering and a non-triggering test and every sample has an expected verdict
  (`tests/fixtures/expected_verdicts.yaml`); `docs/scoring.md`.
- M3 – Asynchronous pipeline and threat intelligence: uploads and the API only store and
  queue (`202 Accepted`); the RQ worker parses, looks up, scores and stores (reply step
  reserved for M5), with 3 retries at 10/30/90 s and a final failure callback; the report
  page polls its status with htmx; VirusTotal (hash, URL, domain), URLhaus (URL, host) and
  RDAP clients behind an HTTPS-only, allow-listed, no-redirect HTTP client; Redis cache
  (24 h / 1 h / 7 d), a Lua token bucket shared by all workers, a daily budget and
  per-report caps; `intel_results` table; `python -m app.cli requeue`;
  `scripts/submit_report.py`; `docs/intel.md`. Acceptance tests: the pipeline runs with no
  keys, mocked answers are stored per observable, and a fake-clock test shows no
  60-second window with more than 4 VirusTotal requests.
- M4 – Analyst console: `users` and `audit_log` tables, argon2id passwords, Redis-backed
  sessions, HMAC CSRF tokens, account and address login throttling,
  `python -m app.cli create-user`; report queue (filters, sort, pages), detail page
  (rules and evidence, headers, Authentication-Results, Received chain, defanged IOCs
  with intel, attachments, sandboxed sanitised HTML body, all headers), analyst verdict,
  notes, "Analyse again", attachment download as an `infected` ZIP, IOC export as CSV
  and STIX 2.1 (per report and in bulk), admin audit log page; `docs/console.md`.
  Acceptance tests: console pages redirect to the login page, a POST without a CSRF
  token gets 403, XSS payloads in subject, display name, file name and body are shown
  escaped, and every STIX export parses with `stix2`.
- M5 – Report mailbox and replies: IMAP poller (UID search, size check, `BODY.PEEK[]`,
  Message-ID de-duplication, `UID MOVE` to `Processed` with a COPY/EXPUNGE fallback,
  oversized messages to `Rejected`), reporter address and DMARC result taken from the
  report email, reply step in the worker with the plan's anti-abuse rules (organisation
  domains, DMARC pass, 20 replies per reporter and hour), plain-text English reply with
  advice per verdict, rule reasons, a defanged subject and the "forward as attachment"
  tip for inline forwards; `reports.reporter_dmarc`, `reply_status` and `replied_at`
  with a migration; reply status on the report page and in the API;
  `GET /api/reports?message_id=`; `samples/` and `scripts/send_sample.py`;
  `docs/mailbox.md`. Acceptance test (`tests/integration/test_mail_flow.py`, run in CI
  against the Compose stack): a sample reported by email is `done` and its reply is in
  Mailpit within one minute; a report from an external address gets no reply.

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

- M2: a rule counts once per email, with all its evidence; `findings` has a unique
  (report_id, rule_id) constraint to match.
- M2: analyzers are pure functions of (email, policy, intel snapshot). M3 looks
  indicators up *before* the analyzers run, so a slow provider cannot stall the rules.
- M2: the 30-second analyzer limit uses threads with a shared deadline, not SIGALRM (RQ
  uses it for job timeouts). An overrunning thread cannot be killed; its result is
  dropped and the report says "partial analysis".
- M2: SENDER_LOOKALIKE_DOMAIN compares whole registered domains (distance 1-2) and also
  the names before the suffix when the protected name has 5+ letters, so the demo's
  `examp1e.example` counts against `example.edu`; same name under another TLD does not.
  Homoglyphs use a small built-in confusables map (code points, no extra dependency).
- M2: SENDER_DISPLAY_NAME_SPOOF and SENDER_FREEMAIL_IMPERSONATION both fire for
  "Payroll Office <x@freemail>": the plan lists them as separate signals.
- M2: AUTH_DKIM_FAIL needs a failed signature and no passing one; one good signature is
  enough (extra broken signatures from mailing lists are common).
- M2: auth and sender rules are skipped for inline forwards (the headers are the
  reporter's); link, attachment and content rules still run.
- M2: macros: an OOXML file with `vbaProject.bin` has macros (no need to parse it);
  otherwise oletools reads the OLE structure, but only if the ZIP listing shows no
  member over 25 MB. XLM (Excel 4.0) macros are not detected yet.
- M2: archive encryption is detected for ZIP only; executables inside a ZIP count for
  ATT_EXECUTABLE; nested archives are not opened.
- M2: evidence values that are indicators are stored defanged; content snippets have
  their URLs defanged too.
- M2: `RULES_FILE` (optional) points to a tuned copy of rules.yaml, e.g. in the mounted
  `config/` directory, so points can change without rebuilding the image.
- M2: two sample emails were made more realistic so that their analyst labels hold
  (07: a tracking link to a bare IP; 08: the "payment advice" asks for the email
  password); the docm in 09 now carries a VBA project skeleton (structure only, no code)
  generated by `scripts/generate_emails.py`.

- M3: pipeline order is parse → extract indicators → intel lookups → rules → score →
  store → reply. The plan lists "analyse" before "intel"; the rules that use intel
  (`*_INTEL_MALICIOUS`, `SENDER_NEW_DOMAIN`) need the answers first, so the static work
  (parsing, attachment inspection, IOC extraction) comes first and the rules run on an
  intel snapshot.
- M3: all slow work (parsing, network lookups) happens before the first database write, so
  no transaction stays open while waiting for a provider; results are stored in one
  transaction.
- M3: RQ calls the failure callback after every failed attempt; it marks the report
  failed only when `retries_left` is 0. A killed work-horse (OOM) does not run callbacks,
  so `requeue --stuck-minutes N` exists for reports that never finish.
- M3: if Redis is down at submission, the report is stored, marked failed ("could not be
  queued") and the client gets 503; nothing is lost and `requeue --failed` retries it.
- M3: `intel_results` has one column the plan does not list, `detail` (a short
  human-readable reason such as "5/70 engines flag it malicious" or "VT_API_KEY not set");
  `raw` keeps only a small fixed subset of each answer (never file names, payload lists
  or WHOIS contacts).
- M3: status semantics: VirusTotal `hit` = at least one engine (malicious from 3, as the
  plan says), URLhaus `hit` = listed, RDAP `hit` = registration date found. URLhaus host
  listings are stored but do not score (shared hosting, shorteners).
- M3: VirusTotal token bucket has capacity 1 (one token per 15 s): any 60-second window
  then holds at most 4 requests even with many workers. The Lua script stores floats with
  `%.17g` so rounding can never release a token early. If Redis is unreachable the
  limiter fails closed (no VirusTotal request). Lookups wait at most 60 s for a token,
  then the rest of that report's VirusTotal lookups are skipped.
- M3: after one provider error the rest of the report's lookups with that provider are
  skipped (no cascade of 10-second timeouts). Only hit/clean/not_found are cached; keys
  hold a SHA-256 of the indicator, never the indicator.
- M3: RDAP servers come from a bundled, reviewed subset of IANA's bootstrap file
  (`app/intel/rdap_bootstrap.json`, refreshed by `scripts/update_rdap_bootstrap.py`)
  rather than a runtime download, so the set of hosts the worker may contact is fixed in
  the repository. Unknown TLDs (and the demo's reserved TLDs) are skipped.
- M3: URLhaus gets a cap of 20 fresh lookups per report; at most 50 results per provider
  are stored per report.
- M3: the offline CLI (`app.cli analyze`) never calls a provider.
- M3: tests block the network with an autouse respx router; three opt-in live tests
  (`-m live`) check the real providers with the user's keys.
- M4: notes are audit-log entries (`report.note`) instead of a ninth table, so the plan's
  data model stays as it is and every note is attributable by construction.
- M4: sessions live in Redis (already part of the stack), not in a table: logout and
  expiry are a key deletion and a TTL. Redis keys hold the SHA-256 of the session token.
  Idle timeout 60 minutes, absolute lifetime 12 hours (`SESSION_IDLE_MINUTES`,
  `SESSION_MAX_HOURS`).
- M4: CSRF uses a stateless HMAC of the browser's cookie token (signed with
  `SECRET_KEY`) instead of a stored token; every visitor gets the cookie, so the login
  form is protected too. The same cookie carries the session token after login (rotated
  on login and logout). POSTs with a foreign or `null` `Origin` are refused as well.
- M4: `Referrer-Policy` changed from `no-referrer` to `same-origin`: under `no-referrer`
  Chromium sends `Origin: null` with form POSTs, which the CSRF check refuses (found
  with a real browser against the Compose stack). Nothing goes to other sites either way.
- M4: the Compose demo sets `SESSION_COOKIE_SECURE=false` (plain http on localhost), as
  the plan allows; `APP_ENV=prod` refuses that setting.
- M4: besides the plan's per-account lock (5 failures / 15 min), 30 failures from one
  address lock that address for 15 minutes, which slows password spraying.
- M4: the audit log page is for the `admin` role; analysts see the activity of each
  report on its page.
- M4: setting an analyst verdict sets `closed_at`; going back to "Automatic" clears both.
  The automatic score and verdict are never overwritten.
- M4: the infected ZIP is written by a small built-in ZipCrypto writer (no extra
  dependency, the format every unzip tool opens); the download name is derived from
  the SHA-256, never from the attacker's file name.
- M4: CSV cells that start with `=`, `+`, `-`, `@`, tab or CR get a leading `'`
  (formula injection). STIX IDs are UUIDv5 so repeated exports de-duplicate;
  subjects and reporter addresses are not exported.
- M4: exports are plain GET downloads, each written to the audit log with its scope
  and counts. The bulk export defaults to malicious + suspicious reports of the last 30
  days and is capped at 5,000 reports.
- M4: "Analyse again" in the console is limited to finished, stand-alone reports;
  re-analysing a split submission rebuilds its reports under new IDs, so that stays a
  CLI operation (`app.cli requeue`).

- M5: three columns on `reports` that the plan's data model does not list:
  `reporter_dmarc` (the DMARC result for the reporter, needed for the reply rule),
  `reply_status` (why a reply was or was not sent, shown to analysts) and `replied_at`
  (the hourly limit counts these rows, so it holds across workers and restarts without
  extra Redis state).
- M5: "the report itself passes DMARC" is read from the topmost `Authentication-Results`
  header with a trusted authserv-id (`policy.trusted_authserv_ids`), the same trust rule
  the analyzers use. The mail server in front of the mailbox must strip such headers
  from incoming mail; docs/mailbox.md says so. PhishTriage does not re-verify DKIM or
  DMARC itself: it is not the receiving MTA and has no SMTP envelope.
- M5: `scripts/send_sample.py` adds the `Authentication-Results` header that the
  organisation's MX would add (`mx.example.edu; dmarc=pass`), because the demo mailbox
  has no mail server in front of it. `--authserv-id ''` sends a report without it.
- M5: the reporter is the `From` address of the report email (the wrapper), never of
  the reported original; mailbox reports take it from there instead of from the caller.
- M5: one reply per submission: when an employee attaches several emails, the first
  report replies once and lists every email with its verdict. Re-analysing never sends
  a second reply.
- M5: a reply failure (SMTP down) is recorded as `reply_status = "failed: ..."` and
  logged, but does not fail or retry the job: the analysis is already stored, and a
  retry would redo the intel lookups.
- M5: messages over the 25 MB limit are moved to a `Rejected` folder without being
  downloaded, so one huge message cannot block the inbox or be fetched every round.
- M5: if Redis is down, the poller stores the report as failed ("could not be queued")
  and still moves the message (same behaviour as the other channels; `requeue --failed`
  retries), then stops the round.
- M5: `GET /api/reports?message_id=` (Bearer token) finds reports by the Message-ID of
  the report email or of a reported email; the end-to-end test needs it to find the
  report it sent by email.
- M5: the version in `app/__init__.py` and `pyproject.toml` is `1.0.0.dev0` until M6.

## Manual steps for the user
- Create the first console account: `docker compose exec web python -m app.cli create-user
  you@example.edu --role admin` (asks for a password of 12+ characters).
- Optional: set `API_TOKEN` in `.env` (at least 32 characters) to enable the REST API.
- Optional: create a VirusTotal account and put `VT_API_KEY` in `.env`.
- Optional: request a URLhaus Auth-Key at https://auth.abuse.ch/ and put `URLHAUS_AUTH_KEY` in `.env`.
- Optional, with keys set: `uv run pytest -m live tests/live` checks the real providers.
- GitHub repository settings: add the topics `phishing`, `email-security`, `soc`,
  `threat-intelligence`, `fastapi`.
