"""
AuthCanary — Engine data models.

Dataclasses consumed by the scoring engine and output layer.
Kept in their own file so scoring.py stays focused on logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal
from ingest.schema import AuthEvent


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    """IP enrichment data — ASN, geo, org."""

    ip: str
    asn: str = "unknown"
    org: str = "unknown"
    country: str = "unknown"
    city: str = "unknown"
    lat: float = 0.0
    lon: float = 0.0
    enriched: bool = False  # False = lookup failed or was skipped

    def to_dict(self) -> dict:
        return asdict(self)


SeverityLevel = Literal["CRITICAL", "WARNING", "NOTICE", "INFO"]


@dataclass(slots=True)
class ScoredEvent:
    """An AuthEvent bundled with enrichment, severity, invariants, novelty, and actionable playbooks."""

    event: AuthEvent
    enrichment: EnrichmentResult | None = None
    severity: SeverityLevel = "INFO"
    invariants: list[str] = field(default_factory=list)
    is_novel: bool = False
    novelty_reasons: list[str] = field(default_factory=list)
    score: int = 0  # Preserved for optional numeric sorting (e.g. CRITICAL=90, WARNING=60, NOTICE=30, INFO=0)
    reasons: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    playbook: str = ""

    def to_dict(self) -> dict:
        return {
            "event": self.event.to_dict(),
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
            "severity": self.severity,
            "invariants": self.invariants,
            "is_novel": self.is_novel,
            "novelty_reasons": self.novelty_reasons,
            "score": self.score,
            "reasons": self.reasons,
            "signals": self.signals,
            "playbook": self.playbook,
        }
