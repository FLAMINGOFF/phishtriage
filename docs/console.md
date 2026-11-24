# Analyst console

The console is where an analyst reviews what the pipeline decided: a queue of reports, a
detail page with all the evidence, a verdict of their own, notes, attachment downloads and
IOC exports. This page explains the pages and the security controls around them.

## Accounts

There is no self-registration. An administrator creates accounts on the command line:

```bash
docker compose exec web python -m app.cli create-user alice@example.edu --role admin
# asks for the password twice, without echo; at least 12 characters
docker compose exec web python -m app.cli create-user bob@example.edu      # analyst
printf '%s\n' "$PASSWORD" | python -m app.cli create-user bob@example.edu --password-stdin --update
```

| Role | Can |
| --- | --- |
| `analyst` | everything in the console except the audit log |
| `admin` | the same, plus the audit log page (`/audit`) |

## Pages

| Page | What it shows |
| --- | --- |
| `/reports` | The queue, 50 per page. Filter by verdict (the analyst's verdict counts where there is one), status and whether an analyst reviewed it; sort by newest, oldest or highest score. Also the bulk IOC export. |
| `/reports/{id}` | Verdict and score, the review forms (verdict, note, "Analyse again"), summary, matched rules with evidence, indicators (defanged) with threat intel, attachments, Authentication-Results (trusted or not), the Received chain, the body, all headers, parser defects and the report's activity. |
| `/reports/{id}/body` | The sanitised HTML body, only ever shown inside `<iframe sandbox>` on the detail page. |
| `/upload` | Upload an `.eml` file. |
| `/audit` | The audit log (admins), filterable by action and user. |

### Verdicts and notes

* Setting a verdict stores it as `analyst_verdict` and closes the report (`closed_at`).
  The automatic score and verdict stay untouched: M6 compares them with the analysts'
  decisions to tune the rule weights. Choosing "Automatic" again re-opens the report.
* A note is a free-text entry (up to 2,000 characters) in the audit log, linked to the
  report. Notes and verdict changes are shown on the report as its activity.
* "Analyse again" re-queues a finished, stand-alone report (useful after adding an intel
  key). A submission that was split into several reports is re-queued with
  `python -m app.cli requeue` instead, because re-analysis rebuilds the split reports
  under new IDs.

### Attachments

An attachment is never served as itself. The download is a ZIP encrypted with the
password `infected`, the convention for passing malware samples around: the file cannot
be opened by a double click, and mail filters and virus scanners leave the archive alone.
The ZIP uses the traditional PKWARE encryption, which every unzip tool opens; it is not
meant to keep the content secret. The name inside the ZIP is cleaned (no directories, no
invisible or direction-changing characters), and the download itself is named after the
file's SHA-256, so an attacker-chosen name never reaches a response header. Once the
retention job has deleted the file the download answers `410 Gone`.

### IOC export

| Export | URL |
| --- | --- |
| One report, CSV | `/reports/{id}/iocs.csv` |
| One report, STIX 2.1 | `/reports/{id}/iocs.stix.json` |
| Recent reports, CSV | `/exports/iocs.csv?verdict=malicious&verdict=suspicious&days=30` |
| Recent reports, STIX 2.1 | `/exports/iocs.stix.json?...` (same parameters) |

* Without `verdict`, the bulk export takes malicious and suspicious reports; `days` is 1
  to 365 (default 30).
* CSV columns: `type, value, defanged, report_id, received_at, verdict, intel`. Cells
  that a spreadsheet would treat as a formula (starting with `=`, `+`, `-`, `@`, tab or
  carriage return) are prefixed with `'`: an attacker can put `=HYPERLINK(...)` into an
  address.
* STIX: one `indicator` per distinct pattern (URL, domain, email address, SHA-256, IPv4,
  IPv6) and one `report` per PhishTriage report, created by a PhishTriage `identity`.
  IDs are UUIDv5 values derived from the pattern or report ID, so exporting twice gives
  the same IDs and a threat-intel platform de-duplicates them. Subjects, bodies and
  reporter addresses are not exported. The bundle is built with the `stix2` library and
  a test parses every export back with it.

## Security controls

| Threat | Control |
| --- | --- |
| Password guessing | argon2id (`argon2-cffi` defaults); 5 failures for one account in 15 minutes lock it for 15 minutes, 30 failures from one address lock that address; one generic error message; an unknown address costs the same hash computation as a known one. |
| Session theft | Server-side sessions in Redis; the cookie holds only a random token (`HttpOnly`, `SameSite=Lax`, `Secure` with the `__Host-` prefix over HTTPS); Redis stores the token's SHA-256, not the token; idle timeout 60 minutes, absolute lifetime 12 hours. |
| Session fixation | Logging in issues a new token; logging out deletes the session and issues a new token. |
| CSRF | Every form carries `HMAC(SECRET_KEY, cookie token)`; htmx sends it as `X-CSRF-Token`. A POST without a valid token, or with a foreign or `null` `Origin`, gets 403. The console's `Referrer-Policy: same-origin` makes browsers send the real `Origin`. |
| XSS from email content | Jinja2 autoescaping everywhere; invisible and direction-changing characters are shown as `<U+202E>`; the HTML body is sanitised (no scripts, styles, links or images) and shown only in `<iframe sandbox>` from a route whose CSP is `default-src 'none'; sandbox`. The console's CSP allows no inline script or style. |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` (the body route allows only its own origin). |
| Open redirect after login | `next` must be a same-site path (`/...`, not `//host` or a URL). |
| Accidental execution of samples | Encrypted ZIP downloads only. |
| Repudiation | Audit log entries for login (success, failure, lock), logout, upload, verdict change, note, re-analysis, attachment download and every export, with user, time and report. |

The API (`/api/...`) does not use cookies: it needs its bearer token (`API_TOKEN`), so it
is not exposed to CSRF.

### Local demo over http

Browsers do not send a `Secure` cookie back over plain http, so the Compose demo sets
`SESSION_COOKIE_SECURE=false`. With `APP_ENV=prod` the application refuses to start with
that setting: in production the console must be served over HTTPS (typically behind a
TLS-terminating reverse proxy).
