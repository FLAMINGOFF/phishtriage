# Evaluation

How well do the rules separate phishing from legitimate mail? This page describes the
method, the tool (`scripts/evaluate.py`), the results so far and what they do and do not
show.

## Method

* **Positive** means the verdict is *malicious* or *suspicious*: those are the verdicts
  that tell the reporter "this is phishing". *Low risk* and *no issues found* count as
  negative.
* Metrics: precision, recall, false-positive rate (legitimate mail flagged), F1 and the
  4-by-2 confusion matrix. The plan's targets are **recall ≥ 90 %** and
  **false-positive rate ≤ 5 %**.
* A threshold sweep shows what recall and false positives would be if "positive" started
  at another score, so a change to the thresholds in `rules.yaml` can be judged before
  it is made. Per-rule hit rates in phishing and in legitimate mail show which rules do
  the work and which ones cause false alarms.
* The analysis is the worker's, run offline: parsing, static attachment inspection,
  the five analyzers and the scoring engine. **No intel lookups** are made (nothing
  leaves the machine), so `*_INTEL_MALICIOUS` and `SENDER_NEW_DOMAIN` never fire. A
  deployment with intelligence enabled needs its own recall and false-positive measurement.
* The data set should look like what a SOC receives: mostly legitimate mail with a
  minority of phishing. With balanced classes precision looks better than it would be.

## Running it

```bash
# The synthetic samples, checked against their analyst labels (exit code 1 on a mismatch)
uv run python scripts/evaluate.py --fixtures

# Real data: files, directories or mbox files; real mail stays in data/private/ (git-ignored)
uv run python scripts/evaluate.py \
    --phish data/private/phishing \
    --ham data/private/easy_ham data/private/hard_ham \
    --show-errors 20                   # list misses and false alarms by file name
uv run python scripts/evaluate.py ... --markdown          # the tables on this page
uv run python scripts/evaluate.py ... --json metrics.json
```

Options: `--policy` takes another policy file (your `org_domains`, protected names and
trusted authserv-ids), `--trust-authserv ID` trusts the `Authentication-Results` of the
data set's receiving server (otherwise the authentication rules see only untrusted
headers, exactly as they would for mail that did not pass through our MX), and `--rules`
evaluates a modified copy of `rules.yaml` without touching the real one.

Suggested public data, as in the plan: phishing from
[phishing_pot](https://github.com/rf-peixoto/phishing_pot) (`.eml` files from honeypots)
or Jose Nazario's phishing corpus (mbox), and legitimate mail from the
[SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)
(`easy_ham`, `hard_ham`). Handle real phishing inside a disposable VM and never open its
attachments; `evaluate.py` only parses them.

## Results

### Synthetic samples

The 15 emails in the 14 samples of `tests/fixtures/emails/` (one sample carries two),
labelled by hand before the rules were tuned (`tests/fixtures/expected_verdicts.yaml`).
CI enforces the exact verdict of every one of them.

| Emails | Precision | Recall | False-positive rate | F1 |
| --- | --- | --- | --- | --- |
| 10 phishing, 5 legitimate | 100.0% | 100.0% | 0.0% | 1.000 |

| Label \ verdict | Malicious | Suspicious | Low risk | No issues found |
| --- | --- | --- | --- | --- |
| Phishing | 6 | 4 | 0 | 0 |
| Legitimate | 0 | 0 | 0 | 5 |

| Positive at score | Recall | False-positive rate |
| --- | --- | --- |
| ≥ 35 | 100.0% | 0.0% |
| ≥ 40 (current) | 100.0% | 0.0% |
| ≥ 45 | 70.0% | 0.0% |
| ≥ 50 | 60.0% | 0.0% |

**What this shows:** every rule does what its description says, on inputs built to
contain each technique (look-alike and punycode domains, forged authentication results,
link-text mismatches, executables behind double extensions, macros, encrypted archives,
GBK and ISO-2022-JP text). **What it does not show:** performance on real mail. The
samples were written alongside the rules, so 100 % here is a regression test, not an
estimate.

### Public corpora — 2026-11-25

**The recall target was not met.** At the unchanged score threshold of 40, both policies
detected only **3 of 101** labelled phishing messages (2.97% recall). A successful
workflow means the experiment ran correctly, not that detection quality passed.

[Verified workflow run](https://github.com/FLAMINGOFF/phishtriage/actions/runs/45516152754)
and [aggregate JSON](public-corpus-2026-11-25.json). No original messages, addresses,
message bodies or per-message indicators are included in the report or artifacts.

#### Data and provenance

All messages from these three archives were evaluated; there was no outcome-based
selection or threshold/weight tuning. The small complete 2021 phishing mailbox was
selected before measuring results because the full phishing_pot collection exceeded
1.5 GB and local downloads were slow. This is a historical baseline, not a current
SOC benchmark.

| Source | Messages | SHA-256 of downloaded file |
| --- | ---: | --- |
| [Jose Nazario, phishing-2021](https://monkey.org/~jose/phishing/phishing-2021) | 101 phishing | `636707cff42245d1482e4ae8a2c03369717a5e06bf9d1a0f4ec5dcd846661cee` |
| [SpamAssassin 20030228 easy_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2) | 2,500 ham | `2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438` |
| [SpamAssassin 20030228 hard_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2) | 250 ham | `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9` |

Downloaded on 2026-11-25. Attribution: Jose Nazario's hand-classified personal-inbox
corpus, [CC BY 4.0 and corpus notes](https://monkey.org/~jose/phishing/README.txt), and
the [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html).
Labels were used as supplied; no independent relabelling was performed. There were
101 unique raw phishing messages, 2,750 unique raw ham messages and no cross-class
exact duplicates by SHA-256. Campaign/near-duplicate clustering was not performed.
Phishing prevalence in this combined set is 3.54%.

Environment: GitHub-hosted Ubuntu 24.04.5, Python 3.12.16, uv 0.11.32,
libmagic 5.45 (`libmagic1t64` 1:5.45-3build1), dependencies from `uv.lock`.
Evaluated commit: `5c08f26c25c4a1e4a366687d19ae5045d467b27a`; the application, rules
and example policy are unchanged from the v1.0.0 M6 snapshot. The 21 evaluation/verdict
regression tests passed. Both runs had **zero parser rejections and zero analysis
errors**. DNS/connect attempts were blocked by a Python audit hook during analysis;
threat intelligence was disabled. Raw mail stayed under ignored `data/private/` in the
ephemeral runner; no raw-mail artifact was uploaded.

#### Policies and results

* **Default:** unmodified `config/settings.example.yaml`, including `example.edu` and
  `mx.example.edu`; no additional trusted Authentication-Results issuers.
* **Brands:** same policy, with `microsoft.com`, `paypal.com`, `apple.com`, `amazon.com`
  appended to protected domains, and Microsoft, PayPal, Apple, Amazon appended to
  protected names. These additions were fixed before seeing results. Organisation
  domains, trusted issuers, rule weights and score thresholds were unchanged.

| Policy | TP | FP | FN | TN | Precision | Recall | False-positive rate | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default | 3 | 45 | 98 | 2705 | 6.25% | 2.97% | 1.64% | 0.0403 |
| brands | 3 | 47 | 98 | 2703 | 6.00% | 2.97% | 1.71% | 0.0397 |

| Policy / label | Malicious | Suspicious | Low risk | No issues found |
| --- | ---: | ---: | ---: | ---: |
| default / phish | 0 | 3 | 46 | 52 |
| default / ham | 1 | 44 | 108 | 2597 |
| brands / phish | 0 | 3 | 50 | 48 |
| brands / ham | 1 | 46 | 106 | 2597 |

Threshold sweep (descriptive only; the deployed threshold remains 40):

| Score threshold | Default recall | Default FPR | Brands recall | Brands FPR |
| --- | ---: | ---: | ---: | ---: |
| 25 | 10.89% | 3.24% | 11.88% | 3.24% |
| 30 | 5.94% | 1.89% | 6.93% | 1.96% |
| 35 | 4.95% | 1.75% | 5.94% | 1.82% |
| 40 | 2.97% | 1.64% | 2.97% | 1.71% |
| 45 | 0.00% | 1.45% | 0.00% | 1.53% |
| 50 | 0.00% | 0.07% | 0.00% | 0.07% |
| 55 | 0.00% | 0.07% | 0.00% | 0.07% |
| 60 | 0.00% | 0.07% | 0.00% | 0.07% |

Default-policy rule hit counts (rates use all 101 phishing / 2,750 ham):

| Rule | Phishing | Ham |
| --- | ---: | ---: |
| `AUTH_NO_TRUSTED_RESULTS` | 99 (98.02%) | 2600 (94.55%) |
| `SENDER_REPLY_TO_MISMATCH` | 4 (3.96%) | 502 (18.25%) |
| `URL_TEXT_HREF_MISMATCH` | 23 (22.77%) | 80 (2.91%) |
| `CONTENT_URGENCY` | 14 (13.86%) | 77 (2.80%) |
| `URL_CREDENTIAL_FORM` | 2 (1.98%) | 86 (3.13%) |
| `CONTENT_CREDENTIAL_REQUEST` | 18 (17.82%) | 5 (0.18%) |
| `ATT_HTML_FILE` | 10 (9.90%) | 0 (0.00%) |
| `URL_SHORTENER` | 2 (1.98%) | 5 (0.18%) |
| `URL_IP_HOST` | 0 (0.00%) | 5 (0.18%) |
| `ATT_EXECUTABLE` | 0 (0.00%) | 1 (0.04%) |

The brand policy additionally matched `SENDER_DISPLAY_NAME_SPOOF` on 4 phishing and
2 ham messages, and `SENDER_FREEMAIL_IMPERSONATION` on 1 phishing message. It added two
false positives without recovering any additional phishing at threshold 40.

#### Misses, false alarms and limits

* **98 misses:** under the default policy 46 were low risk and 52 had no issues found.
  Of those misses, 20 matched link-text/target mismatch, 15 credential requests, 11
  urgency and 10 HTML attachments, but their combined scores remained below 40.
  These counts overlap. The aggregate evidence shows insufficient rule coverage/score
  on this corpus; it does not establish the precise intent of every missed message.
* **45 default false alarms:** 44 matched `URL_CREDENTIAL_FORM`, and 40 matched
  `URL_TEXT_HREF_MISMATCH`. The current form rule matches any HTML form, not just a
  verified credential-stealing form; the mismatch rule compares displayed and target
  domains. These broad heuristics need review on benign HTML mail. One ham message
  matched the executable-attachment rule. Raw attachments were never executed.
* Authentication evidence is mostly absent or untrusted: `AUTH_NO_TRUSTED_RESULTS`
  appeared on 99 phishing and 2,600 ham messages. No corpus sender was granted trust
  to improve scores. A deployment must establish its own receiving-server trust.
* No threshold in the existing 25–60 sweep reached the 90% recall target. Meeting
  the FPR target alone does not make the detector effective. Adding threat intelligence
  requires a separate measurement of both recall and false positives; no improvement
  is assumed here.
* The positive set is only 101 messages from one person's 2021 inbox; the 2002–2003
  negative set predates DMARC. Labels can contain errors, near duplicates can inflate
  apparent evidence, and the two time periods/distributions differ substantially.
  Precision also depends on prevalence. These figures do not estimate modern
  organisation-specific performance and do not validate production readiness.

#### Reproduce

Open **Actions → Public corpus evaluation → Run workflow**. The checked-in workflow
downloads and verifies these exact files, runs the 21 regression tests, evaluates both
fixed policies with network access blocked during analysis, and writes tables to the
job summary plus aggregate JSON to the logs. A checksum change fails the run rather
than silently measuring different data. The original measurement is pinned to the
commit above; later runs on main may use changed code/dependencies.

For a local default-policy run after downloading/extracting the checksum-verified
files under `data/private/`:

```bash
uv sync --locked
uv run pytest tests/unit/test_evaluate.py tests/unit/test_verdicts.py
uv run python scripts/evaluate.py \
  --phish data/private/nazario-phishing-2021.mbox \
  --ham data/private/easy_ham data/private/hard_ham \
  --markdown --json data/private/default-metrics.json
```

The [workflow](../.github/workflows/public-corpus.yml) contains the exact download,
checksum, brand-policy and analysis-error checks. The existing rule and policy hashes
are in the aggregate JSON. No weights were tuned during this evaluation; future
improvements need a separate held-out corpus before making accuracy claims.

## Third measurement after the account-alert follow-up — 2026-11-25

The four reported lures now trigger the credential-request rule in regression tests.
The four routine subscription, billing, address-change and security notices from the
prior review still pass their negative tests. We used the development split and
these regression cases to check the change. The detector was frozen at
`7d02e51abfea7c5e8e9a98691a16fc1d264fce04` before the single final run.

**This is the third measurement on the same held-out data.** The first two results
were already known. The final run reproduced the local development result and used
the same corpus checksums, split, scoring weights and thresholds as the second run.

| Dataset | Second → third detections | Second → third false alarms | Third recall | Third FPR |
| --- | ---: | ---: | ---: | ---: |
| Development (58 phishing, 1,395 ham) | 9 → 9 | 7 → 7 | 15.52% | 0.50% |
| 2021 held-out (43 phishing, 1,355 ham) | 3 → 3 | 6 → 6 | 6.98% | 0.44% |
| 2025 (481 phishing only) | 52 → 53 | N/A | 11.02% | N/A |
| 2021 held-out with the selected mail server trusted | 3 → 3 | 6 → 6 | 6.98% | 0.44% |

On 2021 held-out mail, all recorded aggregates matched the second measurement.
The detector missed 40 of 43 phishing messages. On 2025 mail, the credential rule
matched 83 messages, up from 82, and 53 of 481 reached a positive verdict, up from
52. That collection contains only phishing. The 0.44% false-positive rate comes
from legitimate mail collected in 2003, including in the authentication sensitivity
row. Estimating current performance requires independently held-out recent mail.

No parser rejections or analyzer errors occurred. Locally, 669 tests passed with
96.90% coverage, three were skipped and three live tests were deselected. Ruff,
mypy and the synthetic verdict check passed. [Third measurement](https://github.com/FLAMINGOFF/phishtriage/actions/runs/45529879963) ·
[Aggregate JSON](public-corpus-2026-11-25-account-context.json) · [Second measurement](public-corpus-2026-11-25-review.json).

## Second measurement after PR review — 2026-11-25

Review supplied four legitimate messages about subscription activation, monthly
statements, moving address and enabling two-factor authentication. Regression tests
check that these examples do not trigger the 35-point credential-request rule and
that “No fees apply” still allows a later request with a deadline to trigger it.
Generic account and login requests now require credential, threat or deadline context.

**The held-out figures below are a second measurement after review changes.** The
first results were already known. We ran the development phase first, then the final
phase once at `6054b917ee98e659e00b01c8d800786f6d67b635`. The final run reproduced
the development counts. Both measurements used the same split and the same 2025 mail. [GitHub Actions run](https://github.com/FLAMINGOFF/phishtriage/actions/runs/45528438262) · [Aggregate JSON](public-corpus-2026-11-25-review.json)

| Dataset | Phishing detected, first → second | False alarms, first → second | Second precision | Second recall | Second historical FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Development (58 phishing, 1,395 ham) | 18 → 9 | 7 → 7 | 56.25% | 15.52% | 0.50% |
| 2021 held-out (43 phishing, 1,355 ham) | 7 → 3 | 6 → 6 | 33.33% | 6.98% | 0.44% |
| 2025 phishing (481 phishing only) | 73 → 52 | N/A | N/A | 10.81% | N/A |
| 2021 held-out with the receiving mail server trusted | 7 → 3 | 6 → 6 | 33.33% | 6.98% | 0.44% |

At the 40-point threshold, the revised detector caught four fewer phishing messages
on the 2021 held-out split and 21 fewer on the 2025 corpus. Of the missed phishing
messages, 25/40 from 2021 and 200/429 from 2025 scored zero. Four of the six held-out
false alarms still triggered the credential-request rule. Multiple rules can fire
on one message, so these groups overlap. The parser accepted every message and all
analyzers completed without error.

The historical false-alarm counts stayed the same. The 2003 legitimate mail lacks
comparable authentication headers, including for the experiment that trusted the
receiving mail server. Measuring false alarms on real subscription, account and
security notifications requires recent labelled legitimate mail. The phishing-only
2025 corpus supports a recall estimate only.

Ruff lint and formatting, mypy and the synthetic fixture evaluation passed locally.
The test suite passed 648 tests with 96.88% coverage. Three tests were skipped
and three live tests were deselected.

## Detection tuning — 2026-11-25

### First measurement before PR review

The first tuned detector found 7/43 held-out phishing messages from 2021 and 73/481
from 2025. The baseline found 2/43 and 8/481 respectively. The first tuned detector
flagged 0.44% of the held-out legitimate mail from 2003.
Baseline rows were measured locally. All tuned split and authentication aggregates were
reproduced exactly by the successful [GitHub Actions run](https://github.com/FLAMINGOFF/phishtriage/actions/runs/45526114397)
at `9ddb82a996da2bfe540966db6559f9bf5455f47d` (Ubuntu 24.04, Python 3.12.16).
The aggregate JSON records the remote metadata and canonical result hash.

[First-measurement aggregate JSON](public-corpus-2026-11-25-detection-tuning.json) preserves baseline
and tuned split results separately. The original `public-corpus-2026-11-25.json` is
unchanged. Baseline application: `8ad97e0ccf0f43230c2cd73529a0867b556c827b`.
The tables and error counts below describe the detector frozen at
`9db8cf8330baa499ce6b6040afc813decf348a3e` (application changes in
`7844f381da29c7727ba67e4278711ebdc2cfac87`). The review changes followed this measurement.
Local runtime: Python 3.12.15, macOS arm64, libmagic 5.48, locked dependencies.
The original published baseline used Ubuntu/libmagic 5.45; the before/after rows below
use the same local runtime, and their full baseline counts reproduce the published result.

### Split and provenance

Before inspecting misses or tuning, assign each raw message by its SHA-256 first
hexadecimal digit: `0`–`7` is dev, `8`–`f` is held out. For mbox use
`mailbox.mbox.get_bytes()` (exclude the Unix From envelope); for ham use exact archive
member bytes. Identical raw messages cannot cross the split. The original three
checksum-pinned corpora above produce **58 phishing + 1,395 ham dev** and
**43 phishing + 1,355 ham held out**. There are 101/2,750 unique raw messages and no
cross-class duplicates. The canonical split manifest is the sorted list of
`(sha256, label, split)`, encoded with `json.dumps(..., separators=(",", ":"))`;
its SHA-256 is `1ec75c4d10ebb37b2a68a46fd5a71a759a011c192baa9c523d727bee1a039ff7`.
Only that manifest hash is published, not individual message identifiers.

Additional held-out source: [Jose Nazario phishing-2025](https://monkey.org/~jose/phishing/phishing-2025),
**481 phishing messages**, SHA-256
`f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f`.
It was downloaded/pinned before tuning; its content and errors were not inspected until
after the detector freeze. All 481 raw messages are unique with zero exact overlaps
with 2021. Attribution: Jose Nazario, [CC BY 4.0 and corpus notes](https://monkey.org/~jose/phishing/README.txt).
No near-duplicate or campaign deduplication was performed. Correlated campaigns can
inflate confidence, including across the 2021 random split. The later positive-only
corpus cannot estimate precision, FPR or F1; JSON records these as null, not zero.
No labels were changed and no real messages, addresses or attachment contents are committed.

### Changes selected using dev only

- A form now needs an enabled credential field or an explicit HTTP(S) POST action
  outside the sender organisation. Plain subscription/GET forms no longer count.
- Displayed/target domains from an explicitly configured `org_domains` alias set do not
  mismatch when the sender belongs to that same set. Protected brand lists and unknown
  third-party redirect services do not prove ownership; no corpus-specific whitelist was added.
- Read direct HTML attachments statically for credential forms and text, within strict
  byte/file/character limits. Add passive account-verification and login-to-document
  request patterns; remove invisible format controls and normalise compatibility text.
  Informational sign-in activity alone is not a credential request.
- Credential requests score 35 instead of 15; all other weights and thresholds remain
  unchanged. Keep all 23 IDs and the synthetic analyst labels. Update only expected
  scores/evidence in snapshots. A complete tiny PNG replaces an invalid unit-test stub
  to avoid libmagic-version-dependent tests; attachment detection was not weakened.

Before weights, the first semantic candidate detected 8/58 with 6/1,395 false alarms.
Dev-only credential/urgency weight trials 30/5, 35/5 and 35/10 detected 16, 19 and 19
with seven false alarms each. We selected 35/5 because increasing urgency added no
benefit. Regression review then removed an overly broad informational sign-in match,
leaving the frozen dev result at **18 TP / 7 FP**. The holdout was not used for that
correction. See the explicit rule decisions in [PROGRESS.md](../PROGRESS.md#decision-log)
and semantic limits in [scoring.md](scoring.md).

### Baseline and first tuned measurement at threshold 40

| Data | Version | TP | FN | FP | TN | Precision | Recall | Historical ham FPR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dev (58 / 1,395) | Baseline | 1 | 57 | 22 | 1,373 | 4.35% | 1.72% | 1.58% |
| Dev (58 / 1,395) | Tuned | 18 | 40 | 7 | 1,388 | 72.00% | 31.03% | 0.50% |
| Held out (43 / 1,355) | Baseline | 2 | 41 | 23 | 1,332 | 8.00% | 4.65% | 1.70% |
| Held out (43 / 1,355) | Tuned | 7 | 36 | 6 | 1,349 | 53.85% | 16.28% | 0.44% |
| Extra 2025 (481 / 0) | Baseline | 8 | 473 | N/A | N/A | N/A | 1.66% | N/A |
| Extra 2025 (481 / 0) | Tuned | 73 | 408 | N/A | N/A | N/A | 15.18% | N/A |
| Deployment-like auth, held out | Baseline | 2 | 41 | 23 | 1,332 | 8.00%* | 4.65% | 1.70%* |
| Deployment-like auth, held out | Tuned | 7 | 36 | 6 | 1,349 | 53.85%* | 16.28% | 0.44%* |

Full 2021 + ham quality-gate run after freezing: **25 TP, 76 FN, 13 FP, 2,737 TN**,
recall 24.75%, precision 65.79%, FPR 0.47%. This combines dev and held out and is not
an independent test result. Every corpus run had zero parser rejections and zero
analyzer errors; incomplete analyses fail the public harness instead of silently
improving the denominator. Synthetic verdicts remain 15/15 correct (10 positive, five negative).

### Authentication sensitivity, separate from the headline

Count authserv-ids once per Nazario 2021 message; publish only counts in the JSON.
The most frequent exact ID is `imf11.b.hostedemail.com` (six messages), chosen by
frequency, not outcome. The separate deployment-like row additionally trusts only this
ID, equivalent to `--trust-authserv imf11.b.hostedemail.com`. It appears in three
held-out messages and adds no scoring authentication failures, so detection is unchanged.
Other observed receiving hosts are distributed over many IDs; this single-host test
has low coverage and does not show that authentication is unhelpful.

The copied headers are not independently verified. Trust is restricted to this
experiment and is not written into application policy. **The 2003 ham has no comparable
Authentication-Results: starred precision/FPR describe the historical mix only and do
not validate authentication-related deployment false positives.** Real deployment
requires a controlled receiving MX and representative modern ham.

### Remaining errors and limits in the first measurement

Counts below are overlapping rule-presence groups, not independently verified attack
labels. No attempt was made to relabel the public corpora to improve scores.

- **Dev:** 40 misses, including 19 with zero score; 11 misses contain a credential
  request and six a link-text mismatch but remain below 40. Seven false alarms include
  five cross-domain POST forms, four link mismatches, three Reply-To mismatches, one
  credential request and one executable attachment. The forms include third-party
  newsletter services; accepting all such hosts would also hide attacker destinations.
- **Held out:** 36 misses, including 21 with zero score; five match a credential request,
  five a link mismatch, two a credential form and one an HTML attachment. Six false
  alarms include four credential requests, three forms and three Reply-To mismatches.
  Legitimate account/login requests still resemble phishing and need additional context.
- **Extra 2025:** 408 misses, including 189 with zero score. Among misses, urgency occurs
  127 times, credential requests 50, link mismatches 28 and HTML attachments nine.
  Generic urgency alone remains deliberately weak; a single credential request at 35
  also stays below the suspicious threshold.
- Dev review showed ordinary-looking shared-file/voicemail links, callback scams,
  non-English or visually obfuscated text, and lures inside attachments. The changes
  address only a subset. No image OCR, script execution, nested-archive expansion or
  remote landing-page retrieval was added. Default example policy does not know real
  organisations' brand aliases. Modern ham, campaign-aware sampling and independently
  checked labels are needed before any production claim. The 43-message held-out
  positive set is small, and its performance is materially below dev.

### Reproduce the split evaluation

The workflow retains checksum pinning, count assertions, network-blocking audit hooks
and aggregate-only output. It reads ham bytes from verified archives, avoiding stale
extractions. Local error listings stay under ignored `data/private/`.

```bash
uv sync --locked
# Download the four URLs/checksums in .github/workflows/public-corpus.yml first.
# While tuning: this phase does not load the later corpus or analyse held-out mail.
uv run python scripts/public_corpus.py --phase dev --json data/private/dev.json
# Only after freezing detector code and weights:
uv run python scripts/public_corpus.py --phase final \
  --json data/private/final.json --markdown data/private/final.md
uv run python scripts/evaluate.py --fixtures
uv run python scripts/evaluate.py \
  --phish data/private/nazario-phishing-2021.mbox \
  --ham data/private/easy_ham data/private/hard_ham \
  --show-errors 50 --markdown --json data/private/metrics.json
# Remote aggregate-only evaluation on the review branch:
gh workflow run public-corpus.yml --ref detection-tuning -f phase=final
```

For the before rows, run this same harness using the `app/` and `scripts/evaluate.py`
from `8ad97e0`: create a detached worktree at that commit, copy only
`scripts/public_corpus.py` into its `scripts/`, and invoke it with the current environment's
Python plus `--data-dir /absolute/path/to/data/private --phase final`. The lockfile and
example policy hashes match. The JSON records both code references and rules hashes.

For the first measurement, locked sync, Ruff lint/format, mypy and both evaluation
commands passed. The test suite passed **628 tests** with 96.89% coverage. Three environment-dependent tests were
skipped (two Compose integration tests and one PostgreSQL-only test); three live tests
were deselected as designed. The branch is published as [PR #12](https://github.com/FLAMINGOFF/phishtriage/pull/12);
its Checks tab tracks the final commit's CI, including Compose and PostgreSQL.
The public-corpus Actions run above passed with exactly matching aggregate results.
No main push or merge is authorised for this work. Frank reviews the PR.

## Tuning

The current weights were selected using the dev split above, not the synthetic labels.
Further tuning needs fresh held-out data: the reported held-out sets are now observed.
Keep development diagnostics separate from final evaluation:

1. Fix the split first. Run `--show-errors 50` on dev only and read its errors.
2. Fix rules that fire on the wrong thing first (a bug, not a weight).
3. Then adjust weights or thresholds in a copy, compare with `--rules copy.yaml`, and
   keep a change only if recall rises without the false-positive rate passing 5 %.
4. Re-run `uv run pytest tests/unit/test_verdicts.py`: the synthetic labels must hold.

In production the console provides the same feedback loop: analysts set their own
verdict without overwriting the automatic one, and the statistics page shows how often
they disagreed. Those pairs are labelled data from the organisation's own mail.
