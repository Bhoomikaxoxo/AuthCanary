"""
AuthCanary — Engine data models.

Dataclasses consumed by the scoring engine and output layer.
Kept in their own file so scoring.py stays focused on logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
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


@dataclass(slots=True)
class ScoredEvent:
    """An AuthEvent bundled with enrichment, score, and human-readable reasons."""

    event: AuthEvent
    enrichment: EnrichmentResult | None
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "event": self.event.to_dict(),
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
            "score": self.score,
            "reasons": self.reasons,
        }
