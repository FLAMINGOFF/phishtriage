"""What the analyzers know from threat intelligence.

The worker looks indicators up *before* the analyzers run and hands them a read-only
snapshot, so every analyzer stays a pure function of (email, policy, snapshot): easy to
test, and a slow or failing intel provider never blocks the rule logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Provider = Literal["virustotal", "urlhaus", "rdap"]
IntelStatus = Literal["hit", "clean", "not_found", "skipped", "error"]

# VirusTotal: an indicator counts as malicious from this many engines (fixed by the plan).
VT_MALICIOUS_THRESHOLD = 3


class IntelResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    status: IntelStatus
    malicious_count: int | None = None
    detail: str | None = None  # short human-readable note, e.g. "URLhaus: online, malware_download"

    @property
    def is_malicious(self) -> bool:
        if self.status != "hit":
            return False
        if self.provider == "virustotal":
            return (self.malicious_count or 0) >= VT_MALICIOUS_THRESHOLD
        return self.provider == "urlhaus"


class IntelSnapshot(BaseModel):
    """Lookup results keyed by the observable value (normalised URL, SHA-256, domain)."""

    model_config = ConfigDict(frozen=True)

    urls: dict[str, tuple[IntelResult, ...]] = Field(default_factory=dict)
    hashes: dict[str, tuple[IntelResult, ...]] = Field(default_factory=dict)
    domain_registered: dict[str, datetime] = Field(default_factory=dict)  # from RDAP


EMPTY_SNAPSHOT = IntelSnapshot()
