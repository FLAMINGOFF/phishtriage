"""Run the five analyzers with a time limit each; one failing never sinks the others."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from app.analyzers import attachments, auth, content, sender, urls
from app.analyzers.base import AnalysisContext, Analyzer, AnalyzerName, Hit

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 30.0
ANALYZERS: dict[AnalyzerName, Analyzer] = {
    "auth": auth.analyze,
    "sender": sender.analyze,
    "urls": urls.analyze,
    "attachments": attachments.analyze,
    "content": content.analyze,
}


@dataclass
class AnalyzerRun:
    hits: list[Hit] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # analyzer -> short reason


def run_analyzers(
    ctx: AnalysisContext,
    analyzers: dict[AnalyzerName, Analyzer] | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> AnalyzerRun:
    """Run every analyzer in its own thread with a shared deadline.

    Threads (not signals) because RQ already uses SIGALRM for job timeouts. A thread
    that overruns cannot be killed, but its result is ignored and the report goes on;
    every analyzer works on bounded input, so a real hang would be a bug to fix.
    """
    analyzers = ANALYZERS if analyzers is None else analyzers
    run = AnalyzerRun()
    executor = ThreadPoolExecutor(max_workers=len(analyzers), thread_name_prefix="analyzer")
    try:
        futures = {name: executor.submit(fn, ctx) for name, fn in analyzers.items()}
        deadline = time.monotonic() + timeout
        for name, future in futures.items():
            try:
                run.hits.extend(future.result(timeout=max(0.0, deadline - time.monotonic())))
            except TimeoutError:
                run.errors[name] = f"timed out after {timeout:g} s"
                logger.warning("analyzer %s timed out", name)
            except Exception as exc:
                run.errors[name] = f"failed: {type(exc).__name__}"
                logger.exception("analyzer %s failed", name)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return run
