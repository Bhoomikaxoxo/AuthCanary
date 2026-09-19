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
    accumulates points from each triggered signal. The final score is
    capped at 100.

    Attributes:
        weights: dict mapping signal name → integer weight (from config).
        z_threshold: z-score threshold for unusual-hour detection.
        alert_threshold: score at or above which an event is "alert-level".
        always_alert: list of signal names that trigger an alert regardless
                      of threshold (e.g. "new_ssh_key").
        brute_force_window: minutes to look back for failed logins.
        brute_force_success_window: minutes after failures to look for
                                    a success.
        brute_force_min_failures: minimum failure count to trigger the
                                  brute-force signal.
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

    def score(self, event: AuthEvent,
              enrichment: EnrichmentResult | None,
              baseline: Baseline) -> ScoredEvent:
        """Score a single event against the baseline.

        Returns a ScoredEvent with score, reasons, and the original event
        and enrichment data bundled together.
        """
        score = 0
        reasons: list[str] = []

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
                reasons.append(
                    f"New ASN {enrichment.asn} ({enrichment.org}) "
                    f"never seen for user '{event.username}' (+{w})"
                )
            else:
                # New IP AND new ASN — most suspicious
                w = self.weights["new_ip_new_asn"]
                score += w
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
            reasons.append(
                f"New IP {event.source_ip} for user '{event.username}', "
                f"ASN unknown (enrichment unavailable) (+{w})"
            )

        # ── Signal 3: Unusual login hour ───────────────────────────
        if event.event_type in ("login_success", "login_failure"):
            hour_score = self._score_hour(event, baseline)
            if hour_score > 0:
                score += hour_score
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
            reasons.append(
                f"New SSH key added for user '{event.username}' — "
                f"always flagged (+{w})"
            )

        # ── Signal 5: First-time sudo ─────────────────────────────
        if (event.event_type == "sudo_used"
                and not baseline.is_sudo_user_known(event.username)):
            w = self.weights["first_sudo"]
            score += w
            reasons.append(
                f"First sudo usage by '{event.username}' — "
                f"this user has never used sudo before (+{w})"
            )

        # ── Signal 6: Brute force pattern ──────────────────────────
        if (event.event_type == "login_success" and event.source_ip):
            bf_score = self._score_brute_force(event, baseline)
            if bf_score > 0:
                score += bf_score
                reasons.append(
                    f"Possible brute-force: multiple failed logins from "
                    f"{event.source_ip} followed by success (+{bf_score})"
                )

        # Cap at 100
        final_score = min(100, score)

        return ScoredEvent(
            event=event,
            enrichment=enrichment,
            score=final_score,
            reasons=reasons,
        )

    def is_alert(self, scored: ScoredEvent) -> bool:
        """Should this event trigger an alert?"""
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
