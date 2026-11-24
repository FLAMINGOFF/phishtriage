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
  deployment with VirusTotal and URLhaus keys can only do better on recall.
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

### Public corpora

**Not run yet.** The environment this release was built in had no network access to the
hosts that serve the corpora, and real mail is never committed to the repository. The commands above produce the tables for this section in a few minutes on
any machine with the data; the results, including misses and false alarms by cause, go
here.

What to expect, and to check, on real data:

* **SpamAssassin ham (2002-2003)** predates DMARC and has no `Authentication-Results`.
  Authentication rules will mostly stay silent on it, which makes it an easy negative
  class; the false-positive risk lies in the content rules (`CONTENT_URGENCY`,
  `CONTENT_CREDENTIAL_REQUEST`) on newsletters and account notices, and in
  `URL_SHORTENER` and `URL_TEXT_HREF_MISMATCH` on marketing mail with tracking links.
* **Honeypot phishing** is addressed to the honeypot's own domains, not to
  `example.edu`, so `SENDER_LOOKALIKE_DOMAIN` and `SENDER_DISPLAY_NAME_SPOOF` (which
  compare with the organisation's protected domains and names) fire less than they
  would on phishing aimed at us. A policy listing the brands the corpus imitates
  (Microsoft, PayPal, banks) gives a fairer picture; report both runs.
* Without intel, phishing that is only a link to a fresh domain, with neutral text, will
  be missed. That is the case the intel rules and the analysts are there for.

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
