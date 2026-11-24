#!/usr/bin/env python3
"""Measure the rules on labelled emails: precision, recall, false-positive rate, confusion.

    uv run python scripts/evaluate.py --fixtures             # the synthetic samples
    uv run python scripts/evaluate.py --phish data/private/phishing --ham data/private/ham
    uv run python scripts/evaluate.py ... --markdown          # tables for docs/evaluation.md

``--phish`` and ``--ham`` take files or directories: one ``.eml`` (or extension-less, as
in the SpamAssassin corpus) per message, or ``mbox`` files (as in Jose Nazario's phishing
corpus). Every message is analysed the way the worker analyses a reported original, but
offline: no intel lookups, nothing leaves the machine, attachments are only inspected
statically. Rules that need intel (``*_INTEL_MALICIOUS``, ``SENDER_NEW_DOMAIN``) therefore
never fire here, so the numbers are a lower bound for a deployment with keys.

"Positive" means malicious or suspicious (the plan's definition): those are the verdicts
that tell the reporter it is phishing. Real emails stay in ``data/private/`` (git-ignored)
and are never committed; only the aggregate numbers go into docs/evaluation.md.
"""

from __future__ import annotations

import argparse
import json
import mailbox
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402 - after the path set-up, like the app imports

from app.analysis import analyze_email  # noqa: E402
from app.config import EXAMPLE_SETTINGS_FILE, Policy, load_policy_data  # noqa: E402
from app.db.models import Verdict  # noqa: E402
from app.parsing.eml import MessageRejected, extract_originals  # noqa: E402
from app.scoring.engine import RULES_FILE, VERDICT_LABELS, cached_rules  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "emails"
EXPECTED = ROOT / "tests" / "fixtures" / "expected_verdicts.yaml"
POSITIVE = {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
VERDICTS = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.LOW_RISK, Verdict.NO_ISSUES]
SWEEP = (25, 30, 35, 40, 45, 50, 55, 60)
SKIP_NAMES = {"cmds", "README", "LICENSE", ".DS_Store"}


@dataclass(frozen=True)
class Sample:
    source: str  # file name, plus "#n" for the n-th message of an mbox
    raw: bytes
    label: str  # "phish" or "ham"
    expected: Verdict | None = None  # synthetic fixtures carry an exact expected verdict
    wrapper: bool = False  # a report that carries the original(s), not the original
    index: int = 0  # which original of the report


@dataclass(frozen=True)
class Outcome:
    sample: Sample
    verdict: Verdict | None  # None: rejected by the parser limits
    score: int
    rules: tuple[str, ...]
    forced: bool


@dataclass
class Report:
    outcomes: list[Outcome] = field(default_factory=list)

    def by_label(self, label: str) -> list[Outcome]:
        return [o for o in self.outcomes if o.sample.label == label and o.verdict is not None]

    @property
    def rejected(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.verdict is None]

    def confusion(self) -> dict[str, Counter[Verdict]]:
        return {
            label: Counter(o.verdict for o in self.by_label(label) if o.verdict)
            for label in ("phish", "ham")
        }

    def metrics(self, threshold: int | None = None) -> dict[str, float | int]:
        """Binary metrics; ``threshold`` re-cuts "positive" at another score."""

        def positive(o: Outcome) -> bool:
            if threshold is None:
                return o.verdict in POSITIVE
            return o.forced or o.score >= threshold

        phish, ham = self.by_label("phish"), self.by_label("ham")
        tp = sum(positive(o) for o in phish)
        fp = sum(positive(o) for o in ham)
        fn, tn = len(phish) - tp, len(ham) - fp
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / len(phish) if phish else 0.0
        fpr = fp / len(ham) if ham else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {
            "phish": len(phish),
            "ham": len(ham),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
            "f1": f1,
        }

    def rule_rates(self) -> list[tuple[str, int, int, float, float]]:
        """(rule, phish hits, ham hits, share of phish, share of ham), most frequent first."""
        phish, ham = self.by_label("phish"), self.by_label("ham")
        in_phish = Counter(r for o in phish for r in o.rules)
        in_ham = Counter(r for o in ham for r in o.rules)
        rows = []
        for rule in sorted(set(in_phish) | set(in_ham)):
            rows.append(
                (
                    rule,
                    in_phish[rule],
                    in_ham[rule],
                    in_phish[rule] / len(phish) if phish else 0.0,
                    in_ham[rule] / len(ham) if ham else 0.0,
                )
            )
        return sorted(rows, key=lambda r: (-(r[1] + r[2]), r[0]))

    def fixture_mismatches(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.sample.expected and o.verdict != o.sample.expected]


# --------------------------------------------------------------------------- loading


def _is_mbox(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(5) == b"From "


def _messages(path: Path) -> Iterator[tuple[str, bytes]]:
    if _is_mbox(path):
        box = mailbox.mbox(path, create=False)
        try:
            for index, key in enumerate(box.iterkeys()):
                yield f"{path.name}#{index}", box.get_bytes(key)
        finally:
            box.close()
    else:
        yield path.name, path.read_bytes()


def load(paths: Iterable[Path], label: str) -> Iterator[Sample]:
    for path in paths:
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for file in files:
            if file.name in SKIP_NAMES or file.name.startswith("."):
                continue
            for source, raw in _messages(file):
                yield Sample(source=source, raw=raw, label=label)


def load_fixtures() -> Iterator[Sample]:
    """The synthetic samples with their analyst labels (tests/fixtures/expected_verdicts.yaml).

    A fixture can carry several originals (a report with two attached emails); each one
    is a sample of its own.
    """
    expected = yaml.safe_load(EXPECTED.read_text(encoding="utf-8"))
    for stem, verdicts in sorted(expected.items()):
        [path] = sorted(FIXTURES.glob(f"{stem}.eml"))
        for index, value in enumerate(verdicts):
            verdict = Verdict(value)
            yield Sample(
                source=f"{path.name}#{index}" if len(verdicts) > 1 else path.name,
                raw=path.read_bytes(),
                label="phish" if verdict in POSITIVE else "ham",
                expected=verdict,
                # Same naming rule as tests/unit/test_verdicts.py.
                wrapper="report" in stem or "inline_forward" in stem,
                index=index,
            )


# --------------------------------------------------------------------------- analysis


def evaluate(samples: Iterable[Sample], policy: Policy, rules_file: Path | None = None) -> Report:
    report = Report()
    now = datetime.now(UTC)
    for sample in samples:
        try:
            intake = extract_originals(sample.raw, is_report_wrapper=sample.wrapper)
            parsed = intake.originals[sample.index]
        except MessageRejected:
            report.outcomes.append(Outcome(sample, None, 0, (), False))
            continue
        result = analyze_email(parsed, policy, now=now, rules_file=rules_file).result
        report.outcomes.append(
            Outcome(
                sample,
                result.verdict,
                result.score,
                tuple(f.rule_id for f in result.findings),
                result.forced_by is not None,
            )
        )
    return report


# --------------------------------------------------------------------------- output


def _pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def render_text(report: Report, show_errors: int) -> str:
    m = report.metrics()
    lines = [
        f"phishing: {m['phish']}  legitimate: {m['ham']}  rejected by the parser: "
        f"{len(report.rejected)}",
        f"precision {_pct(float(m['precision']))}  recall {_pct(float(m['recall']))}  "
        f"false-positive rate {_pct(float(m['false_positive_rate']))}  F1 {float(m['f1']):.3f}",
        f"TP {m['tp']}  FP {m['fp']}  FN {m['fn']}  TN {m['tn']}",
        "",
        "confusion (rows: label, columns: verdict)",
    ]
    confusion = report.confusion()
    lines.append(f"{'':8}" + "".join(f"{VERDICT_LABELS[v.value]:>18}" for v in VERDICTS))
    for label in ("phish", "ham"):
        lines.append(f"{label:8}" + "".join(f"{confusion[label][v]:>18}" for v in VERDICTS))
    lines += ["", "threshold sweep (positive = score >= T, or a forced verdict)"]
    for t in SWEEP:
        s = report.metrics(t)
        lines.append(
            f"  T={t:>2}: recall {_pct(float(s['recall'])):>6}  "
            f"false-positive rate {_pct(float(s['false_positive_rate'])):>6}  "
            f"precision {_pct(float(s['precision'])):>6}"
        )
    lines += ["", "rules (hits in phishing / legitimate)"]
    for rule, hp, hh, sp, sh in report.rule_rates():
        lines.append(f"  {rule:34} {hp:>5} ({_pct(sp):>6})  {hh:>5} ({_pct(sh):>6})")
    if show_errors:
        misses = [o for o in report.by_label("phish") if o.verdict not in POSITIVE]
        alarms = [o for o in report.by_label("ham") if o.verdict in POSITIVE]
        for title, items in (("missed phishing", misses), ("false alarms", alarms)):
            lines += ["", f"{title} (first {show_errors})"]
            for o in items[:show_errors]:
                verdict = o.verdict.value if o.verdict else "rejected"
                lines.append(f"  {o.sample.source}: {verdict} {o.score} {','.join(o.rules)}")
    mismatches = report.fixture_mismatches()
    if mismatches:
        lines += ["", "fixtures with an unexpected verdict"]
        for o in mismatches:
            got = o.verdict.value if o.verdict else "rejected"
            want = o.sample.expected.value if o.sample.expected else "?"
            lines.append(f"  {o.sample.source}: expected {want}, got {got}")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    m = report.metrics()
    confusion = report.confusion()
    out = [
        "| Emails | Precision | Recall | False-positive rate | F1 |",
        "| --- | --- | --- | --- | --- |",
        f"| {m['phish']} phishing, {m['ham']} legitimate | {_pct(float(m['precision']))} | "
        f"{_pct(float(m['recall']))} | {_pct(float(m['false_positive_rate']))} | "
        f"{float(m['f1']):.3f} |",
        "",
        "| Label \\ verdict | " + " | ".join(VERDICT_LABELS[v.value] for v in VERDICTS) + " |",
        "| --- |" + " --- |" * len(VERDICTS),
    ]
    for label, name in (("phish", "Phishing"), ("ham", "Legitimate")):
        out.append(f"| {name} | " + " | ".join(str(confusion[label][v]) for v in VERDICTS) + " |")
    out += [
        "",
        "| Positive at score | Recall | False-positive rate | Precision |",
        "| --- | --- | --- | --- |",
    ]
    for t in SWEEP:
        s = report.metrics(t)
        out.append(
            f"| ≥ {t} | {_pct(float(s['recall']))} | {_pct(float(s['false_positive_rate']))} | "
            f"{_pct(float(s['precision']))} |"
        )
    out += ["", "| Rule | Phishing | Legitimate |", "| --- | --- | --- |"]
    for rule, hp, hh, sp, sh in report.rule_rates():
        out.append(f"| `{rule}` | {hp} ({_pct(sp)}) | {hh} ({_pct(sh)}) |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phish", nargs="+", type=Path, default=[], help="phishing emails")
    parser.add_argument("--ham", nargs="+", type=Path, default=[], help="legitimate emails")
    parser.add_argument("--fixtures", action="store_true", help="the labelled synthetic samples")
    parser.add_argument("--policy", type=Path, help="policy file (default: the example policy)")
    parser.add_argument(
        "--trust-authserv",
        action="append",
        default=[],
        metavar="ID",
        help="also trust Authentication-Results from this authserv-id (repeatable)",
    )
    parser.add_argument("--rules", type=Path, help="rules file (default: app/scoring/rules.yaml)")
    parser.add_argument("--markdown", action="store_true", help="print Markdown tables")
    parser.add_argument("--json", type=Path, help="also write the metrics as JSON")
    parser.add_argument(
        "--show-errors", type=int, default=0, metavar="N", help="list N misses and false alarms"
    )
    args = parser.parse_args(argv)
    if not (args.fixtures or args.phish or args.ham):
        parser.error("give --fixtures, or --phish and/or --ham")

    data = load_policy_data(args.policy or EXAMPLE_SETTINGS_FILE)
    if args.trust_authserv:
        data["trusted_authserv_ids"] = [*data.get("trusted_authserv_ids", []), *args.trust_authserv]
    policy = Policy.model_validate(data)
    cached_rules(args.rules or RULES_FILE)  # fail early on a broken rules file

    samples: list[Sample] = []
    if args.fixtures:
        samples += load_fixtures()
    samples += load(args.phish, "phish")
    samples += load(args.ham, "ham")
    report = evaluate(samples, policy, args.rules)

    print(render_markdown(report) if args.markdown else render_text(report, args.show_errors))
    if args.json:
        payload = {
            "metrics": report.metrics(),
            "sweep": {str(t): report.metrics(t) for t in SWEEP},
            "confusion": {
                label: {v.value: count for v, count in counter.items()}
                for label, counter in report.confusion().items()
            },
            "rejected": len(report.rejected),
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 1 if report.fixture_mismatches() else 0


if __name__ == "__main__":
    sys.exit(main())
