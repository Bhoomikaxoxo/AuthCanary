"""
AuthCanary — Anomaly scoring engine.

Each new event gets a numeric anomaly score (0–100) based on how much
it deviates from the user's established baseline. This file is entirely
self-contained: you can read and understand the full scoring logic here
without tracing through any other module.

Score components and their weights are loaded from config.yaml — no
magic numbers are hard-coded in this file.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult, ScoredEvent
from engine.baseline import Baseline
from engine.playbooks import get_playbook


# ── Default weights (overridden by config.yaml) ───────────────────

DEFAULT_WEIGHTS = {
    "new_asn": 30,
    "new_ip_known_asn": 15,
    "new_ip_new_asn": 35,
    "unusual_hour": 20,
    "new_ssh_key": 40,
    "first_sudo": 30,
    "brute_force_pattern": 35,
}


class Scorer:
    """Assigns an anomaly score (0–100) to each AuthEvent.

    The scorer compares the event against the per-user baseline and
    accumulates points from each triggered signal. If multi-event attack
    sequences are detected within a rolling window, a sequence multiplier
    and chain bonus are applied BEFORE the score is capped at 100.
    """

    def __init__(self, config: dict) -> None:
        scoring_cfg = config.get("scoring", {})
        self.weights = {**DEFAULT_WEIGHTS, **scoring_cfg.get("weights", {})}
        self.z_threshold = scoring_cfg.get("z_score_threshold", 2.0)
        self.alert_threshold = scoring_cfg.get("alert_threshold", 60)
        self.always_alert = scoring_cfg.get("always_alert", ["new_ssh_key"])
        self.brute_force_window = scoring_cfg.get("brute_force_window_min", 10)
        self.brute_force_success_window = scoring_cfg.get(
            "brute_force_success_min", 5)
        self.brute_force_min_failures = scoring_cfg.get(
            "brute_force_min_failures", 3)

        # Correlation & sequence scoring settings
        correlation_cfg = config.get("correlation", {})
        self.sequence_window_min = correlation_cfg.get("sequence_window_min", 15)
        self.sequence_multiplier = correlation_cfg.get("sequence_multiplier", 1.5)

    def score(self, event: AuthEvent,
              enrichment: EnrichmentResult | None,
              baseline: Baseline) -> ScoredEvent:
        """Score a single event against the baseline.

        Returns a ScoredEvent with score, reasons, and the original event
        and enrichment data bundled together.
        """
        score = 0
        reasons: list[str] = []
        signals: list[str] = []

        # ── Signal 1: New ASN ──────────────────────────────────────
        if (enrichment and enrichment.enriched
                and enrichment.asn not in ("unknown", "private")
                and event.source_ip
                and not baseline.is_asn_known(event.username, enrichment.asn)):

            ip_known = baseline.is_ip_known(event.username, event.source_ip)

            if ip_known:
                # Known IP, new ASN (unlikely but possible — ISP change)
                w = self.weights["new_asn"]
                score += w
                signals.append("new_asn")
                reasons.append(
                    f"New ASN {enrichment.asn} ({enrichment.org}) "
                    f"never seen for user '{event.username}' (+{w})"
                )
            else:
                # New IP AND new ASN — most suspicious
                w = self.weights["new_ip_new_asn"]
                score += w
                signals.append("new_ip_new_asn")
                reasons.append(
                    f"New IP {event.source_ip} from unknown ASN "
                    f"{enrichment.asn} ({enrichment.org}, "
                    f"{enrichment.city}, {enrichment.country}) "
                    f"for user '{event.username}' (+{w})"
                )

        # ── Signal 2: New IP, known ASN ────────────────────────────
        elif (event.source_ip
              and not baseline.is_ip_known(event.username, event.source_ip)
              and enrichment and enrichment.enriched
              and baseline.is_asn_known(event.username, enrichment.asn)):
            w = self.weights["new_ip_known_asn"]
            score += w
            signals.append("new_ip_known_asn")
            reasons.append(
                f"New IP {event.source_ip} but from known ASN "
                f"{enrichment.asn} for user '{event.username}' (+{w})"
            )

        # ── Signal 2b: New IP, enrichment unavailable ──────────────
        elif (event.source_ip
              and not baseline.is_ip_known(event.username, event.source_ip)
              and (not enrichment or not enrichment.enriched)):
            # Can't tell if ASN is new — use a moderate weight
            w = self.weights["new_ip_known_asn"]
            score += w
            signals.append("new_ip_known_asn")
            reasons.append(
                f"New IP {event.source_ip} for user '{event.username}', "
                f"ASN unknown (enrichment unavailable) (+{w})"
            )

        # ── Signal 3: Unusual login hour ───────────────────────────
        if event.event_type in ("login_success", "login_failure"):
            hour_score = self._score_hour(event, baseline)
            if hour_score > 0:
                score += hour_score
                signals.append("unusual_hour")
                try:
                    hour = datetime.fromisoformat(event.timestamp).hour
                except ValueError:
                    hour = -1
                reasons.append(
                    f"Login at hour {hour:02d}:00 is unusual for "
                    f"user '{event.username}' (+{hour_score})"
                )

        # ── Signal 4: New SSH key ──────────────────────────────────
        if event.event_type == "ssh_key_added":
            w = self.weights["new_ssh_key"]
            score += w
            signals.append("new_ssh_key")
            reasons.append(
                f"New SSH key added for user '{event.username}' — "
                f"always flagged (+{w})"
            )

        # ── Signal 5: First-time sudo ─────────────────────────────
        if (event.event_type == "sudo_used"
                and not baseline.is_sudo_user_known(event.username)):
            w = self.weights["first_sudo"]
            score += w
            signals.append("first_sudo")
            reasons.append(
                f"First sudo usage by '{event.username}' — "
                f"this user has never used sudo before (+{w})"
            )

        # ── Signal 6: Brute force pattern ──────────────────────────
        if (event.event_type == "login_success" and event.source_ip):
            bf_score = self._score_brute_force(event, baseline)
            if bf_score > 0:
                score += bf_score
                signals.append("brute_force_pattern")
                reasons.append(
                    f"Possible brute-force: multiple failed logins from "
                    f"{event.source_ip} followed by success (+{bf_score})"
                )

        # ── Sequence Correlation & Multi-Stage Attack Chains ───────
        recent_events = baseline.get_recent_user_events(
            event.username,
            window_minutes=self.sequence_window_min,
            current_timestamp=event.timestamp,
        )

        past_signals = set(s for r in recent_events for s in r.get("signals", []))

        has_initial_access = any(
            s in past_signals or s in signals
            for s in ("new_asn", "new_ip_new_asn", "brute_force_pattern")
        )
        has_escalation = "first_sudo" in past_signals or "first_sudo" in signals or event.event_type == "sudo_used"
        has_persistence = "new_ssh_key" in past_signals or "new_ssh_key" in signals or event.event_type == "ssh_key_added"

        seq_mult = 1.0
        seq_bonus = 0

        # Chain 1: Full post-compromise kill chain (Access → Escalation → Persistence)
        if has_initial_access and has_escalation and has_persistence and len(recent_events) > 0:
            signals.append("kill_chain")
            seq_mult = max(self.sequence_multiplier, 1.8)
            seq_bonus = 40
            reasons.append(
                f"🚨 CRITICAL KILL CHAIN: Multi-stage post-compromise sequence detected within "
                f"{self.sequence_window_min}m (Initial Access → Privilege Escalation → Persistence) "
                f"[{seq_mult}x multiplier +{seq_bonus}]"
            )
        # Chain 2: Initial access followed by privilege escalation
        elif (has_initial_access and (event.event_type == "sudo_used" or "first_sudo" in signals)
              and any(s in past_signals for s in ("new_asn", "new_ip_new_asn", "brute_force_pattern"))):
            signals.append("correlated_escalation")
            seq_mult = self.sequence_multiplier
            seq_bonus = 25
            reasons.append(
                f"🚨 Correlated Sequence: Privilege escalation (sudo) preceded by novel remote access "
                f"within {self.sequence_window_min}m [{seq_mult}x multiplier +{seq_bonus}]"
            )
        # Chain 3: Initial access followed by persistence planting
        elif (has_initial_access and (event.event_type == "ssh_key_added" or "new_ssh_key" in signals)
              and any(s in past_signals for s in ("new_asn", "new_ip_new_asn"))):
            signals.append("correlated_persistence")
            seq_mult = self.sequence_multiplier
            seq_bonus = 30
            reasons.append(
                f"🚨 Correlated Sequence: Persistence mechanism planted ({event.event_type}) preceded by "
                f"novel remote access within {self.sequence_window_min}m [{seq_mult}x multiplier +{seq_bonus}]"
            )

        # ── Order of Operations: Multipliers applied BEFORE the 100-cap ──
        # NOTE: Multipliers and chain bonuses must compound on the raw score first.
        # The 100-point ceiling is enforced strictly as the final step.
        correlated_score = int(score * seq_mult) + seq_bonus
        final_score = min(100, correlated_score)

        playbook = get_playbook(
            signals=signals,
            user=event.username,
            ip=event.source_ip or "unknown",
            asn=enrichment.asn if enrichment else "unknown",
            city=enrichment.city if enrichment else "",
            country=enrichment.country if enrichment else "",
        )

        return ScoredEvent(
            event=event,
            enrichment=enrichment,
            score=final_score,
            reasons=reasons,
            signals=signals,
            playbook=playbook,
        )

    def is_alert(self, scored: ScoredEvent) -> bool:
        """Should this event trigger an alert?"""
        # Correlated attack chains always alert
        if any(s in scored.signals for s in ("kill_chain", "correlated_escalation", "correlated_persistence")):
            return True

        # Always-alert signals
        for signal in self.always_alert:
            if signal == "new_ssh_key" and scored.event.event_type == "ssh_key_added":
                return True

        return scored.score >= self.alert_threshold

    # ── Internal scoring helpers ───────────────────────────────────

    def _score_hour(self, event: AuthEvent, baseline: Baseline) -> int:
        """Score how unusual the login hour is for this user.

        Uses a z-score against the per-user hour histogram. If the hour
        has literally zero historical occurrences, full weight is applied.
        """
        try:
            hour = datetime.fromisoformat(event.timestamp).hour
        except ValueError:
            return 0

        histogram = baseline.get_hour_histogram(event.username)
        total = sum(histogram)

        if total == 0:
            # No history at all — can't score
            return 0

        count_at_hour = histogram[hour]
        w = self.weights["unusual_hour"]

        # Zero occurrences at this hour = full weight
        if count_at_hour == 0:
            return w

        # Z-score: how many standard deviations from the mean?
        mean = total / 24
        variance = sum((h - mean) ** 2 for h in histogram) / 24
        std = math.sqrt(variance) if variance > 0 else 0

        if std == 0:
            # Uniform distribution — nothing is unusual
            return 0

        z = (mean - count_at_hour) / std  # Inverted: low count = high z
        if z > self.z_threshold:
            # Scale weight by how extreme the z-score is
            scale = min(1.0, z / (self.z_threshold * 2))
            return int(w * scale)

        return 0

    def _score_brute_force(self, event: AuthEvent,
                           baseline: Baseline) -> int:
        """Detect brute-force pattern: N failures → success from same IP.

        Looks for >= brute_force_min_failures login_failure events from
        the same IP within the brute_force_window, followed by this
        login_success within brute_force_success_window.
        """
        try:
            event_time = datetime.fromisoformat(event.timestamp)
        except ValueError:
            return 0

        window_start = (
            event_time - timedelta(minutes=self.brute_force_window)
        ).isoformat()

        failures = baseline.get_recent_failures(
            event.username, event.source_ip, window_start  # type: ignore[arg-type]
        )

        if failures >= self.brute_force_min_failures:
            return self.weights["brute_force_pattern"]

        return 0
