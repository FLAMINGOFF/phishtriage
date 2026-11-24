"""What the analyzers know from threat intelligence.

The worker looks indicators up *before* the rules run and hands the analyzers a read-only
snapshot, so every analyzer stays a pure function of (email, policy, snapshot): easy to
test, and a slow or failing intel provider never blocks the rule logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Provider = Literal["virustotal", "urlhaus", "rdap"]
IntelStatus = Literal["hit", "clean", "not_found", "skipped", "error"]

PROVIDER_LABELS: dict[str, str] = {
    "virustotal": "VirusTotal",
    "urlhaus": "URLhaus",
    "rdap": "RDAP",
}

# VirusTotal: an indicator counts as malicious from this many engines (fixed by the plan).
VT_MALICIOUS_THRESHOLD = 3

# Only definite answers are cached. "skipped" and "error" say nothing about the indicator,
# so caching them would only delay the real lookup.
CACHEABLE_STATUSES: frozenset[str] = frozenset({"hit", "clean", "not_found"})


class IntelResult(BaseModel):
    """One provider's answer about one indicator.

    ``status`` meanings: ``hit`` the provider has something on it (VirusTotal: at least one
    engine flags it; URLhaus: it is listed; RDAP: a registration date was found), ``clean``
    known and not flagged, ``not_found`` unknown to the provider, ``skipped`` not looked up
    (no key, rate limit, budget), ``error`` the lookup failed. ``raw`` keeps a small, fixed
    subset of the provider's response, never the whole document.
    """

    model_config = ConfigDict(frozen=True)

    provider: Provider
    status: IntelStatus
    malicious_count: int | None = None
    detail: str | None = None  # short human-readable note, e.g. "online, malware_download"
    raw: dict[str, Any] = Field(default_factory=dict)
    fetched_at: datetime | None = None

    @property
    def is_malicious(self) -> bool:
        if self.status != "hit":
            return False
        if self.provider == "virustotal":
            return (self.malicious_count or 0) >= VT_MALICIOUS_THRESHOLD
        return self.provider == "urlhaus"

    @classmethod
    def skipped(cls, provider: Provider, reason: str) -> IntelResult:
        return cls(provider=provider, status="skipped", detail=reason)

    @classmethod
    def error(cls, provider: Provider, reason: str) -> IntelResult:
        return cls(provider=provider, status="error", detail=reason)


class IntelSnapshot(BaseModel):
    """Lookup results keyed by the observable value (normalised URL, SHA-256, domain)."""

    model_config = ConfigDict(frozen=True)

    urls: dict[str, tuple[IntelResult, ...]] = Field(default_factory=dict)
    hashes: dict[str, tuple[IntelResult, ...]] = Field(default_factory=dict)
    domain_registered: dict[str, datetime] = Field(default_factory=dict)  # from RDAP


EMPTY_SNAPSHOT = IntelSnapshot()
