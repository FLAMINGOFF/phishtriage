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

## Tuning

The rule weights in `app/scoring/rules.yaml` are the plan's starting values. They were
not tuned on the synthetic samples, because fitting weights to fifteen hand-written
emails would only fit those emails. Tuning follows the public-corpus run:

1. Run with `--show-errors 50` and read the misses and false alarms.
2. Fix rules that fire on the wrong thing first (a bug, not a weight).
3. Then adjust weights or thresholds in a copy, compare with `--rules copy.yaml`, and
   keep a change only if recall rises without the false-positive rate passing 5 %.
4. Re-run `uv run pytest tests/unit/test_verdicts.py`: the synthetic labels must hold.

In production the console provides the same feedback loop: analysts set their own
verdict without overwriting the automatic one, and the statistics page shows how often
they disagreed. Those pairs are labelled data from the organisation's own mail.
