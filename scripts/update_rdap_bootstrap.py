"""Add or refresh TLDs in app/intel/rdap_bootstrap.json from IANA's RDAP bootstrap registry.

    uv run python scripts/update_rdap_bootstrap.py com net org io co
    uv run python scripts/update_rdap_bootstrap.py --all

The worker only ever contacts the RDAP servers listed in that file, so review the diff
before committing it. Only HTTPS servers are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

IANA_URL = "https://data.iana.org/rdap/dns.json"
TARGET = Path(__file__).resolve().parent.parent / "app" / "intel" / "rdap_bootstrap.json"


def fetch(url: str = IANA_URL) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed IANA URL
        data: dict[str, Any] = json.load(response)
        return data


def services_by_tld(data: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for tlds, urls in data["services"]:
        https = [u for u in urls if u.startswith("https://")]
        if https:
            for tld in tlds:
                result[tld.lower()] = https
    return result


def merge(current: dict[str, Any], iana: dict[str, Any], tlds: list[str] | None) -> dict[str, Any]:
    known = services_by_tld(current)
    fresh = services_by_tld(iana)
    wanted = sorted(fresh) if tlds is None else [t.lower().lstrip(".") for t in tlds]
    missing = [t for t in wanted if t not in fresh]
    if missing:
        print(f"not in the IANA registry (no RDAP service): {', '.join(missing)}", file=sys.stderr)
    for tld in wanted:
        if tld in fresh:
            known[tld] = fresh[tld]
    grouped: dict[tuple[str, ...], list[str]] = {}
    for tld, urls in sorted(known.items()):
        grouped.setdefault(tuple(urls), []).append(tld)
    return {
        "description": current.get("description", ""),
        "publication": iana.get("publication", "unknown"),
        "services": [[tlds_, list(urls)] for urls, tlds_ in grouped.items()],
        "version": iana.get("version", "1.0"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tlds", nargs="*", help="TLDs to add or refresh, e.g. com net io")
    parser.add_argument("--all", action="store_true", help="take every TLD from IANA")
    args = parser.parse_args(argv)
    if not args.tlds and not args.all:
        parser.error("name some TLDs or pass --all")
    current = json.loads(TARGET.read_text(encoding="utf-8"))
    updated = merge(current, fetch(), None if args.all else args.tlds)
    TARGET.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {TARGET}; review the diff before committing", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
