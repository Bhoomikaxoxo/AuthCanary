"""
SentinelLog — Alert channels.

ConsoleChannel is always active. NtfyChannel sends push notifications
to a free ntfy.sh topic (no signup required). The --serve flag and
Gmail SMTP are documented stretch goals — not implemented in v1.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests

from engine.models import ScoredEvent


class AlertChannel(ABC):
    """Interface for alert delivery."""

    @abstractmethod
    def send(self, scored: ScoredEvent) -> bool:
        """Send an alert. Returns True on success."""
        ...


class ConsoleChannel(AlertChannel):
    """Print high-severity alerts to stdout (always-on fallback)."""

    def send(self, scored: ScoredEvent) -> bool:
        event = scored.event
        reasons = "; ".join(scored.reasons)
        print(
            f"🚨 ALERT [score {scored.score}/100] "
            f"{event.event_type} by '{event.username}' "
            f"at {event.timestamp}"
        )
        print(f"   Reasons: {reasons}")
        if event.source_ip:
            print(f"   Source IP: {event.source_ip}")
        print()
        return True


class NtfyChannel(AlertChannel):
    """Send push notifications via ntfy.sh (free, no signup).

    Configure in config.yaml:
        alerts:
          ntfy:
            enabled: true
            topic: "sentinellog-alerts"
            server: "https://ntfy.sh"
    """

    def __init__(self, topic: str, server: str = "https://ntfy.sh") -> None:
        self.url = f"{server.rstrip('/')}/{topic}"

    def send(self, scored: ScoredEvent) -> bool:
        event = scored.event
        title = (
            f"AuthCanary Alert [{scored.score}/100]: "
            f"{event.event_type} by {event.username}"
        )
        body = "\n".join(scored.reasons)
        if event.source_ip:
            body += f"\nSource IP: {event.source_ip}"

        # Map score to ntfy priority (1–5)
        if scored.score >= 85:
            priority = "5"
            tags = "rotating_light"
        elif scored.score >= 70:
            priority = "4"
            tags = "warning"
        else:
            priority = "3"
            tags = "eyes"

        try:
            resp = requests.post(
                self.url,
                data=body.encode("utf-8"),
                headers={
                    "Title": title,
                    "Priority": priority,
                    "Tags": tags,
                },
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False


def get_channels(config: dict) -> list[AlertChannel]:
    """Build the list of active alert channels from config."""
    channels: list[AlertChannel] = []

    alerts_cfg = config.get("alerts", {})

    if alerts_cfg.get("console", True):
        channels.append(ConsoleChannel())

    ntfy_cfg = alerts_cfg.get("ntfy", {})
    if ntfy_cfg.get("enabled", False):
        channels.append(NtfyChannel(
            topic=ntfy_cfg.get("topic", "authcanary-alerts"),
            server=ntfy_cfg.get("server", "https://ntfy.sh"),
        ))

    return channels
