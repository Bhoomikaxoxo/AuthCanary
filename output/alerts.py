"""
AuthCanary — Alert channels.

Supports Console, ntfy.sh push notifications, generic JSON Webhooks,
Slack incoming webhooks, and Discord webhook embeds.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

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
        if scored.playbook:
            print("   📋 Suggested Playbook:")
            for line in scored.playbook.splitlines():
                print(f"      {line}")
        print()
        return True


class NtfyChannel(AlertChannel):
    """Send push notifications via ntfy.sh (free, no signup).

    Configure in config.yaml:
        alerts:
          ntfy:
            enabled: true
            topic: "authcanary-alerts"
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
        body_parts = scored.reasons[:]
        if scored.playbook:
            body_parts.append("\n📋 Playbook:\n" + scored.playbook)
        body = "\n".join(body_parts)
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


class WebhookChannel(AlertChannel):
    """Send structured JSON alerts to a generic HTTP/HTTPS endpoint."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> None:
        self.url = url
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update(headers)
        self.timeout = timeout

    def send(self, scored: ScoredEvent) -> bool:
        try:
            payload = scored.to_dict()
            resp = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            return resp.status_code in (200, 201, 202, 204)
        except requests.RequestException:
            return False


class SlackWebhookChannel(AlertChannel):
    """Send rich formatted alert notifications to Slack via Incoming Webhooks."""

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def send(self, scored: ScoredEvent) -> bool:
        event = scored.event
        score = scored.score
        severity = scored.severity or ("CRITICAL" if score >= 80 else "WARNING" if score >= 50 else "INFO")

        if severity == "CRITICAL" or score >= 80:
            color = "#E01E5A"  # Red
            icon = "🚨"
        elif severity == "WARNING" or score >= 50:
            color = "#ECB22E"  # Amber
            icon = "⚠️"
        else:
            color = "#2EB886"  # Green
            icon = "ℹ️"

        reasons_text = "\n• " + "\n• ".join(scored.reasons) if scored.reasons else "None specified"
        fields: list[dict[str, Any]] = [
            {"title": "User", "value": f"`{event.username}`", "short": True},
            {"title": "Event Type", "value": f"`{event.event_type}`", "short": True},
            {"title": "Severity", "value": severity, "short": True},
            {"title": "Risk Score", "value": f"{score}/100", "short": True},
        ]
        if event.source_ip:
            fields.append({"title": "Source IP", "value": f"`{event.source_ip}`", "short": True})
        if scored.enrichment and scored.enrichment.enriched:
            loc = f"{scored.enrichment.city}, {scored.enrichment.country} ({scored.enrichment.org})"
            fields.append({"title": "Geo / Org", "value": loc, "short": True})

        ts_epoch = None
        try:
            ts_epoch = int(datetime.fromisoformat(event.timestamp).timestamp())
        except Exception:
            pass

        attachment: dict[str, Any] = {
            "color": color,
            "title": f"{icon} AuthCanary Alert: {event.event_type}",
            "text": f"*Reasons:*{reasons_text}",
            "fields": fields,
            "footer": "AuthCanary Security Monitor",
        }
        if ts_epoch:
            attachment["ts"] = ts_epoch

        if scored.playbook:
            attachment["text"] += f"\n\n*📋 Recommended Playbook:*\n```{scored.playbook}```"

        payload = {
            "text": f"{icon} *AuthCanary Alert:* [{severity}] {event.event_type} on `{event.username}`",
            "attachments": [attachment],
        }

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False


class DiscordWebhookChannel(AlertChannel):
    """Send formatted embed alerts to Discord via Webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        username: str = "AuthCanary",
        timeout: int = 10,
    ) -> None:
        self.webhook_url = webhook_url
        self.username = username
        self.timeout = timeout

    def send(self, scored: ScoredEvent) -> bool:
        event = scored.event
        score = scored.score
        severity = scored.severity or ("CRITICAL" if score >= 80 else "WARNING" if score >= 50 else "INFO")

        if severity == "CRITICAL" or score >= 80:
            color = 0xE01E5A  # Red
            icon = "🚨"
        elif severity == "WARNING" or score >= 50:
            color = 0xF1C40F  # Gold
            icon = "⚠️"
        else:
            color = 0x2ECC71  # Green
            icon = "ℹ️"

        embed_fields: list[dict[str, Any]] = [
            {"name": "User", "value": f"`{event.username}`", "inline": True},
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Score", "value": f"{score}/100", "inline": True},
            {"name": "Event Type", "value": f"`{event.event_type}`", "inline": True},
        ]
        if event.source_ip:
            embed_fields.append({"name": "Source IP", "value": f"`{event.source_ip}`", "inline": True})
        if scored.enrichment and scored.enrichment.enriched:
            loc = f"{scored.enrichment.city}, {scored.enrichment.country} ({scored.enrichment.org})"
            embed_fields.append({"name": "Geo / Org", "value": loc, "inline": True})

        reasons_desc = "\n• " + "\n• ".join(scored.reasons) if scored.reasons else "None specified"
        description = f"**Reasons:**{reasons_desc}"

        if scored.playbook:
            description += f"\n\n**📋 Playbook:**\n```{scored.playbook}```"

        embed: dict[str, Any] = {
            "title": f"{icon} AuthCanary Security Alert: {event.event_type}",
            "description": description,
            "color": color,
            "fields": embed_fields,
            "footer": {"text": "AuthCanary Triage Monitor"},
        }
        if event.timestamp:
            embed["timestamp"] = event.timestamp

        payload = {
            "username": self.username,
            "embeds": [embed],
        }

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            return resp.status_code in (200, 204)
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

    webhook_cfg = alerts_cfg.get("webhook", {})
    if webhook_cfg.get("enabled", False) and webhook_cfg.get("url"):
        channels.append(WebhookChannel(
            url=webhook_cfg["url"],
            headers=webhook_cfg.get("headers"),
            timeout=webhook_cfg.get("timeout", 10),
        ))

    slack_cfg = alerts_cfg.get("slack", {})
    if slack_cfg.get("enabled", False) and slack_cfg.get("webhook_url"):
        channels.append(SlackWebhookChannel(
            webhook_url=slack_cfg["webhook_url"],
            timeout=slack_cfg.get("timeout", 10),
        ))

    discord_cfg = alerts_cfg.get("discord", {})
    if discord_cfg.get("enabled", False) and discord_cfg.get("webhook_url"):
        channels.append(DiscordWebhookChannel(
            webhook_url=discord_cfg["webhook_url"],
            username=discord_cfg.get("username", "AuthCanary"),
            timeout=discord_cfg.get("timeout", 10),
        ))

    return channels

