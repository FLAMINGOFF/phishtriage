#!/usr/bin/env python3
"""Checksum-pinned, aggregate-only public evaluation with a predeclared raw-byte split.

Use --phase dev while tuning. --phase final is reserved for a frozen detector: it
also evaluates the held-out half, the later year and a separate auth experiment.
No individual message identifiers, text, addresses or URLs are emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import evaluate as ev  # noqa: E402

CORPORA = {
    "nazario-phishing-2021.mbox": {
        "url": "https://monkey.org/~jose/phishing/phishing-2021",
        "sha256": "636707cff42245d1482e4ae8a2c03369717a5e06bf9d1a0f4ec5dcd846661cee",
        "count": 101,
    },
    "easy_ham.tar.bz2": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "sha256": "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438",
        "count": 2500,
    },
    "hard_ham.tar.bz2": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "sha256": "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9",
        "count": 250,
    },
    "nazario-phishing-2025.mbox": {
        "url": "https://monkey.org/~jose/phishing/phishing-2025",
        "sha256": "f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f",
        "count": 481,
    },
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def split_name(raw: bytes) -> str:
    return "dev" if int(digest(raw)[0], 16) < 8 else "heldout"


def offline(event: str, _args: tuple[Any, ...]) -> None:
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto"}:
        raise RuntimeError("Network access forbidden during corpus evaluation")


def load_source(directory: Path, name: str) -> list[ev.Sample]:
    path = directory / name
    expected = CORPORA[name]
    if digest(path.read_bytes()) != expected["sha256"]:
        raise ValueError(f"Checksum mismatch: {name}")
    if name.endswith(".mbox"):
        samples = list(ev.load([path], "phish"))
    else:
        samples = []
        # Read verified archive members as bytes; no extraction/traversal and no stale
        # local extraction can silently change the evaluation data.
        with tarfile.open(path, "r:bz2") as archive:
            for member in archive:
                if not member.isfile() or Path(member.name).name in ev.SKIP_NAMES:
                    continue
                handle = archive.extractfile(member)
                assert handle is not None
                with handle:
                    samples.append(ev.Sample(member.name, handle.read(), "ham"))
    if "count" in expected:
        assert len(samples) == expected["count"], f"Unexpected count: {name}"
    return samples


def summarize(report: ev.Report) -> dict[str, Any]:
    metrics: dict[str, Any] = report.metrics()
    if not metrics["ham"]:
        # A positive-only corpus cannot estimate precision or a false-positive rate.
        metrics["precision"] = metrics["false_positive_rate"] = metrics["f1"] = None
    misses = [o for o in report.by_label("phish") if o.verdict not in ev.POSITIVE]
    alarms = [o for o in report.by_label("ham") if o.verdict in ev.POSITIVE]
    return {
        "metrics": metrics,
        "rejected": len(report.rejected),
        "confusion": {label: dict(counts) for label, counts in report.confusion().items()},
        "rule_rates": report.rule_rates(),
        "false_negative_rule_counts": dict(Counter(r for o in misses for r in o.rules)),
        "false_positive_rule_counts": dict(Counter(r for o in alarms for r in o.rules)),
        "misses_with_zero_score": sum(o.score == 0 for o in misses),
    }


def measured(samples: list[ev.Sample], policy: ev.Policy) -> dict[str, Any]:
    original = ev.analyze_email
    failures: Counter[str] = Counter()

    def checked(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        failures.update(result.errors.keys())
        return result

    ev.analyze_email = checked
    try:
        report = ev.evaluate(samples, policy)
    finally:
        ev.analyze_email = original
    if failures or report.rejected:
        raise RuntimeError("Incomplete analysis; do not publish partial metrics")
    return {**summarize(report), "analysis_errors": dict(failures)}


def run(directory: Path, phase: str) -> dict[str, Any]:
    samples = [s for name in list(CORPORA)[:3] for s in load_source(directory, name)]
    splits = {
        name: [s for s in samples if split_name(s.raw) == name] for name in ("dev", "heldout")
    }
    counts = {name: dict(Counter(s.label for s in group)) for name, group in splits.items()}
    assert counts == {"dev": {"phish": 58, "ham": 1395}, "heldout": {"phish": 43, "ham": 1355}}
    # Commit only the manifest hash, not per-message hashes or source paths.
    manifest = sorted((digest(s.raw), s.label, split_name(s.raw)) for s in samples)
    fingerprints = {
        label: {digest(s.raw) for s in samples if s.label == label} for label in ("phish", "ham")
    }
    assert len(fingerprints["phish"]) == 101
    assert len(fingerprints["ham"]) == 2750
    assert not fingerprints["phish"] & fingerprints["ham"]
    policy = ev.Policy.model_validate(ev.load_policy_data(ev.EXAMPLE_SETTINGS_FILE))
    result: dict[str, Any] = {
        "metadata": {
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "phase": phase,
            "split": "sha256(raw_message)[0] < 8 hexadecimal => dev; otherwise heldout",
            "split_counts": counts,
            "manifest_sha256": digest(json.dumps(manifest, separators=(",", ":")).encode()),
            "rules_sha256": digest(ev.RULES_FILE.read_bytes()),
            "policy_sha256": digest(ev.EXAMPLE_SETTINGS_FILE.read_bytes()),
            "lock_sha256": digest((ROOT / "uv.lock").read_bytes()),
            "corpora": {
                name: spec
                for name, spec in CORPORA.items()
                if phase == "final" or "2025" not in name
            },
            "unique_raw_messages": {label: len(values) for label, values in fingerprints.items()},
            "cross_class_duplicates": 0,
            "near_duplicate_deduplication": False,
        },
        "runs": {"dev": measured(splits["dev"], policy)},
    }
    if phase == "dev":
        return result  # Never load the later year or analyse held-out data during tuning.
    result["runs"]["heldout"] = measured(splits["heldout"], policy)
    extra = load_source(directory, "nazario-phishing-2025.mbox")
    extra_hashes = {digest(s.raw) for s in extra}
    result["metadata"]["extra_unique_raw_messages"] = len(extra_hashes)
    result["metadata"]["extra_overlap_with_2021"] = len(extra_hashes & fingerprints["phish"])
    result["runs"]["extra_2025"] = measured(extra, policy)
    auth_ids: Counter[str] = Counter()
    for sample in samples:
        if sample.label == "phish":
            parsed = ev.extract_originals(sample.raw, is_report_wrapper=False).originals[0]
            auth_ids.update({h.authserv_id for h in parsed.authentication_results if h.authserv_id})
    result["authentication"] = {"messages_by_authserv_id": dict(auth_ids)}
    if auth_ids:
        auth_id = sorted(auth_ids, key=lambda key: (-auth_ids[key], key))[0]
        trusted = policy.model_copy(
            update={"trusted_authserv_ids": (*policy.trusted_authserv_ids, auth_id)}
        )
        result["authentication"]["selected_id"] = auth_id
        deployment = measured(splits["heldout"], trusted)
        deployment["caveat"] = (
            "Deployment-like sensitivity only: historical ham lacks comparable trusted "
            "authentication; FPR is not validated."
        )
        result["runs"]["deployment_like_heldout"] = deployment
    return result


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Public corpus evaluation",
        "",
        "Offline static analysis; historical data, not deployment accuracy.",
        "",
        "| Run | Phish | Ham | TP | FP | Recall | FPR |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, run in result["runs"].items():
        m = run["metrics"]
        fpr = "N/A" if m["false_positive_rate"] is None else f"{m['false_positive_rate']:.2%}"
        lines.append(
            f"| {name} | {m['phish']} | {m['ham']} | {m['tp']} | {m['fp']} | "
            f"{m['recall']:.2%} | {fpr} |"
        )
    lines += [
        "",
        "Deployment-like authentication is a separate sensitivity experiment. Its ham side "
        "does not validate deployment FPR. No near-duplicate/campaign deduplication was performed.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data/private")
    parser.add_argument("--phase", choices=("dev", "final"), default="dev")
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    sys.addaudithook(offline)
    result = run(args.data_dir, args.phase)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.write_text(markdown(result), encoding="utf-8")
    print("AGGREGATE_RESULTS_BEGIN")
    print(json.dumps(result, sort_keys=True))
    print("AGGREGATE_RESULTS_END")


if __name__ == "__main__":
    main()
