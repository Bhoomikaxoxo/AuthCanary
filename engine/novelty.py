"""
AuthCanary — Novelty Diff Ledger (Zero-Math Baseline).

Maintains a factual inventory of known entities (users, sudo commands,
remote IPs, ASNs, and auth methods) to identify genuine first-seen activity
without arbitrary point scores.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ingest.schema import AuthEvent
    from engine.models import EnrichmentResult
    from engine.baseline import Baseline


class NoveltyTracker:
    """Evaluates whether an event introduces new entities or behavior to the host."""

    def evaluate(
        self,
        event: AuthEvent,
        enrichment: EnrichmentResult | None,
        baseline: Baseline,
    ) -> tuple[bool, list[str]]:
        """Check if any attribute in this event is first-seen on the host.

        Returns:
            (is_novel, novelty_reasons)
        """
        reasons: list[str] = []
        user = event.username or "system"

        # 1. First-time Sudo command
        if event.process == "sudo" and event.command and hasattr(baseline, "is_sudo_command_known"):
            if not baseline.is_sudo_command_known(user, event.command):
                reasons.append(f"First execution of sudo command '{event.command}' by user '{user}'")

        # 2. First-time Sudo user
        if (event.event_type in ("sudo_used", "privilege_elevation") or event.process == "sudo") and not baseline.is_sudo_user_known(user):
            reasons.append(f"First sudo / privilege elevation usage by user '{user}'")

        # 3. First-time Remote IP (exclude local host)
        if event.source_ip and event.source_ip not in ("127.0.0.1", "::1", "localhost") and not baseline.is_ip_known(user, event.source_ip):
            ip_desc = event.source_ip
            if enrichment and enrichment.enriched:
                ip_desc += f" ({enrichment.city}, {enrichment.country})"
            reasons.append(f"First-seen remote IP {ip_desc} for user '{user}'")

        # 4. First-time Remote ASN
        if (
            enrichment
            and enrichment.enriched
            and enrichment.asn not in ("unknown", "private")
            and not baseline.is_asn_known(user, enrichment.asn)
        ):
            reasons.append(
                f"First-seen network provider {enrichment.asn} ({enrichment.org}) for user '{user}'"
            )

        # 5. First-time SSH key
        if event.event_type == "ssh_key_added":
            reasons.append(f"New SSH authorized key added for user '{user}'")

        is_novel = len(reasons) > 0
        return is_novel, reasons
