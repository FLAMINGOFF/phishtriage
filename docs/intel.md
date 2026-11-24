# Asynchronous pipeline and threat intelligence

This page explains what happens after a report is submitted: the queue, the worker, the
threat-intel lookups and the limits around them. Scoring itself is in
[scoring.md](scoring.md).

## From submission to verdict

```mermaid
sequenceDiagram
    participant C as Upload / API / poller
    participant W as web
    participant R as Redis (RQ)
    participant K as worker
    participant P as VirusTotal · URLhaus · RDAP
    participant D as PostgreSQL
    C->>W: raw .eml
    W->>D: store bytes (blob store) + report status=queued
    W->>R: enqueue report ID (JSON, never pickle)
    W-->>C: 202 Accepted (API) / report page that polls
    R->>K: job app.jobs.process_report(id)
    K->>D: status=analyzing
    K->>K: parse, extract indicators
    K->>P: look up hashes, URLs, hosts, sender domain
    K->>K: rules on email + intel snapshot, score
    K->>D: email, attachments, IOCs, intel results, findings, verdict; status=done
    K->>K: reply to reporter (M5)
```

* The **web process never parses email**. It stores the bytes, creates the report and puts
  its ID on the queue. Parsing hostile input happens only in the worker.
* **Statuses**: `queued → analyzing → done`, or `failed` with a reason in `error`
  (`rejected: …` for input that is not an email or breaks a limit; `processing failed …`
  after the retries are used up).
* **Retries**: a crash or timeout makes RQ retry the job up to **3 times**, after 10, 30
  and 90 seconds (exponential back-off, factor 3). The job is idempotent: each attempt
  starts by removing what an earlier one wrote. RQ's scheduler, which runs inside the
  worker (`with_scheduler=True`), puts delayed retries back on the queue.
* **Polling**: `POST /api/reports` answers `202 Accepted` with a `Location` header; poll
  `GET /api/reports/{id}` (or run `scripts/submit_report.py`, which does it for you). The
  report page polls `/reports/{id}/status` every 2 seconds with htmx and reloads itself
  when the worker is done.
* **If Redis is down** at submission time, the report is still stored but marked failed
  ("could not be queued"), and the client gets `503`. Re-queue later with
  `python -m app.cli requeue --failed` (or `--stuck-minutes 15` for reports that never
  finished, or explicit report IDs).

## What is looked up

| Provider | Indicators | Endpoint | Counts for |
| --- | --- | --- | --- |
| VirusTotal | attachment SHA-256, then URLs, then domains | `GET /api/v3/files/{sha256}`, `GET /api/v3/urls/{id}`, `GET /api/v3/domains/{domain}` | `ATT_INTEL_MALICIOUS`, `URL_INTEL_MALICIOUS` (≥ 3 engines) |
| URLhaus | URLs; domains and IPs | `POST /v1/url/`, `POST /v1/host/` | `URL_INTEL_MALICIOUS` (URL listed) |
| RDAP | registered domain of the sender | `GET {server}/domain/{domain}` | `SENDER_NEW_DOMAIN` (< 30 days) |

Rules never wait for the network: the worker collects all answers into a read-only
snapshot first and then runs the analyzers on it, so a slow provider cannot stall them.

A URLhaus **host** listing is stored for the analyst but does not score: shared hosting
and link shorteners often have one bad URL among millions of good ones.

### What never leaves the server

* **Attachments are never uploaded.** Only their SHA-256 is looked up. Files uploaded to
  VirusTotal are shared with its customers, and an attachment may hold confidential data.
* **URLs are never submitted for scanning.** VirusTotal URL lookups use the URL identifier
  (`GET /urls/{id}`), which reads the existing report; `POST /urls` (a new scan) is not
  implemented. A test asserts the client has no other public method.
* **Links are never visited.** The worker only talks to the providers. The HTTP client
  refuses any host that is not VirusTotal, URLhaus or an RDAP server from the bundled
  bootstrap file, refuses plain HTTP, never follows redirects and refuses answers over 5 MB.

## Statuses of a lookup

| Status | Meaning |
| --- | --- |
| `hit` | VirusTotal: at least one engine flags it (malicious from 3). URLhaus: listed. RDAP: a registration date was found. |
| `clean` | VirusTotal knows it and no engine flags it. |
| `not_found` | Unknown to the provider (VirusTotal 404, URLhaus `no_results`, no RDAP record). |
| `skipped` | Not looked up: no key, per-report cap, rate limit, daily budget, no RDAP server for the TLD. The reason is stored. |
| `error` | The lookup failed (timeout, HTTP error, bad answer). The reason is stored. |

Missing keys and provider failures never fail the analysis; the report is scored without
that intel. After one error, the rest of that report's lookups with the same provider are
skipped instead of waiting for more timeouts.

## Caching

Answers are cached in Redis under `intel:v1:{provider}:{kind}:{sha256(indicator)}` (the key
never contains the indicator itself):

| Provider | TTL |
| --- | --- |
| VirusTotal | 24 hours |
| URLhaus | 1 hour |
| RDAP | 7 days |

Only definite answers (`hit`, `clean`, `not_found`) are cached; `skipped` and `error` would
only delay the real lookup. A broken cache is a cache miss, never a failed analysis. A
cached answer keeps its original `fetched_at`.

## VirusTotal rate limit and budget

The free public API allows **4 requests per minute and 500 per day**, and must not be used
in commercial products or services. A real deployment at an institution needs a paid
licence (then raise `VT_RATE_PER_MINUTE` and `VT_DAILY_BUDGET`).

* **Token bucket** in Redis, shared by all workers: capacity 1, one token every
  `60 / VT_RATE_PER_MINUTE` seconds (15 s). With a capacity of one, two requests are
  always at least 15 s apart, so **no 60-second window can hold more than 4**. The bucket
  is updated by a single Lua script, so two workers can never take the same token.
  `tests/unit/test_intel_service.py` proves the bound with a fake clock, for one worker
  and for eight competing ones.
* **Waiting**: a lookup waits for a token for at most `INTEL_MAX_WAIT_SECONDS` (60); after
  that it, and the rest of that report's VirusTotal lookups, are skipped with
  "rate limit".
* **Daily budget**: a counter per UTC day (`intel:budget:virustotal:{date}`); at
  `VT_DAILY_BUDGET` (500) further lookups are skipped until the next day.
* **Per report**: at most `VT_MAX_LOOKUPS_PER_REPORT` (4) fresh lookups, hashes first, then
  URLs, then domains. Cached answers do not count.
* **Fail closed**: if Redis cannot be reached, VirusTotal is not called at all.

URLhaus has no published hard limit; the worker still caps it at 20 fresh lookups per report.

## RDAP servers

RDAP (the JSON successor of WHOIS) servers are chosen per TLD from
`app/intel/rdap_bootstrap.json`, a reviewed subset of IANA's
[bootstrap registry](https://data.iana.org/rdap/dns.json). The file is part of the
repository on purpose: the set of servers the worker may contact is fixed and reviewed
like code, not downloaded at run time. Domains under other TLDs are skipped (the
`SENDER_NEW_DOMAIN` rule then does not fire). To add TLDs:

```bash
uv run python scripts/update_rdap_bootstrap.py com net org io co   # from IANA
git diff app/intel/rdap_bootstrap.json                              # review, then commit
```

Reserved demo TLDs (`.example`, `.test`) have no RDAP server, so the demo never sends
RDAP queries.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `VT_API_KEY` | unset | VirusTotal key; unset = VirusTotal lookups skipped |
| `URLHAUS_AUTH_KEY` | unset | abuse.ch Auth-Key; unset = URLhaus lookups skipped |
| `VT_RATE_PER_MINUTE` | 4 | token-bucket refill rate |
| `VT_DAILY_BUDGET` | 500 | VirusTotal requests per UTC day |
| `VT_MAX_LOOKUPS_PER_REPORT` | 4 | fresh VirusTotal lookups per report |
| `INTEL_MAX_WAIT_SECONDS` | 60 | longest wait for a rate-limit slot |
| `INTEL_TIMEOUT_SECONDS` | 10 | HTTP timeout per lookup |
| `RDAP_ENABLED` | true | RDAP needs no key; set false to send no RDAP queries |

`python -m app.cli check-config` shows what is configured (keys masked).

## Testing

* Unit tests never touch the network: an autouse `respx` router makes any HTTP request
  without a matching mock fail. Provider answers are mocked per test.
* `tests/unit/test_jobs.py` runs the whole job without keys (everything `skipped`, verdict
  still computed) and with mocked providers (results stored per observable, a hash hit
  forces `malicious`), and drives a real RQ worker against fakeredis to check retries and
  the final failure.
* `tests/live/` holds three opt-in tests against the real services (RDAP for
  `example.com`, the EICAR hash on VirusTotal, URLhaus for `example.com`):
  `VT_API_KEY=… URLHAUS_AUTH_KEY=… uv run pytest -m live tests/live`.
