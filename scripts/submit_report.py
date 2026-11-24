"""Submit an .eml file to a running PhishTriage through the REST API and wait for the verdict.

    API_TOKEN=... python scripts/submit_report.py suspicious.eml

Standard library only, so it runs anywhere (CI, a laptop without the project installed).
``--expect-verdict`` makes it a smoke test: the exit code is 1 on any other outcome.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


def call(method: str, url: str, token: str, body: bytes | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, data=body, method=method)  # noqa: S310 - our own API
    request.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        request.add_header("Content-Type", "message/rfc822")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        result: dict[str, Any] = json.load(response)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", type=Path)
    parser.add_argument(
        "--base-url", default=os.environ.get("PHISHTRIAGE_BASE_URL", DEFAULT_BASE_URL)
    )
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds to wait")
    parser.add_argument("--expect-verdict", help="exit 1 unless the report ends with this verdict")
    args = parser.parse_args(argv)

    token = os.environ.get("API_TOKEN", "")
    if not token:
        print("set API_TOKEN (the same value as in .env)", file=sys.stderr)
        return 2
    base = args.base_url.rstrip("/")
    try:
        report = call("POST", f"{base}/api/reports", token, args.file.read_bytes())
        print(f"queued report {report['id']}", file=sys.stderr)
        deadline = time.monotonic() + args.timeout
        while report["status"] in ("queued", "analyzing") and time.monotonic() < deadline:
            time.sleep(1)
            report = call("GET", f"{base}/api/reports/{report['id']}", token)
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"cannot reach {base}: {exc}", file=sys.stderr)
        return 1

    summary = {
        "id": report["id"],
        "status": report["status"],
        "verdict": report["verdict"],
        "score": report["score"],
        "findings": [f["rule_id"] for f in report["findings"]],
        "error": report["error"],
        "web": f"{base}/reports/{report['id']}",
    }
    print(json.dumps(summary, indent=2))
    if report["status"] != "done":
        return 1
    if args.expect_verdict and report["verdict"] != args.expect_verdict:
        print(f"expected verdict {args.expect_verdict}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
