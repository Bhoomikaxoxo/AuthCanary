"""
AuthCanary — Tests for the output layer.

Tests report generation (JSON + HTML dashboard) and alert delivery channels
(ConsoleChannel and NtfyChannel with mocked HTTP).
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult, ScoredEvent
from engine.baseline import Baseline
from output.report import generate_report
from output.alerts import (
    ConsoleChannel,
    NtfyChannel,
    WebhookChannel,
    SlackWebhookChannel,
    DiscordWebhookChannel,
    get_channels,
)


# ── Report Generation Tests ────────────────────────────────────────

def test_generate_report_creates_files():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "baseline.db"
        b = Baseline(str(db_path))

        out_dir = Path(tmp_dir) / "output"
        config = {
            "output": {"directory": str(out_dir)},
            "scoring": {"alert_threshold": 40},
        }

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="185.220.101.34",
            auth_method="password",
        )
        enr = EnrichmentResult(
            ip="185.220.101.34",
            asn="AS208323",
            org="Tor Exit",
            country="DE",
            city="Frankfurt",
            enriched=True,
        )
        scored = ScoredEvent(
            event=ev,
            enrichment=enr,
            score=55,
            reasons=["New IP 185.220.101.34 (+35)", "Unusual hour (+20)"],
        )

        json_path, html_path = generate_report(
            scored_events=[scored],
            baseline=b,
            config=config,
            skip_warmup=True,
        )

        assert json_path.exists()
        assert html_path.exists()

        # Validate JSON content
        with open(json_path) as f:
            data = json.load(f)

        assert data["warmup_complete"] is True
        assert data["alert_threshold"] == 40
        assert data["anomaly_count"] == 1
        assert len(data["scored_events"]) == 1
        assert data["scored_events"][0]["score"] == 55
        assert data["scored_events"][0]["event"]["username"] == "alice"

        # Validate HTML content
        html_content = html_path.read_text(encoding="utf-8")
        assert "AuthCanary" in html_content
        assert "alice" in html_content
        assert "185.220.101.34" in html_content
        assert "AS208323" in html_content
        assert "55" in html_content


def test_generate_report_zero_anomalies():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "baseline.db"
        b = Baseline(str(db_path))

        out_dir = Path(tmp_dir) / "output"
        config = {
            "output": {"directory": str(out_dir)},
            "scoring": {"alert_threshold": 40},
        }

        json_path, html_path = generate_report(
            scored_events=[],
            baseline=b,
            config=config,
            skip_warmup=True,
        )

        with open(json_path) as f:
            data = json.load(f)

        assert data["anomaly_count"] == 0
        assert len(data["scored_events"]) == 0

        html_content = html_path.read_text(encoding="utf-8")
        assert "0" in html_content


# ── Alert Channel Tests ────────────────────────────────────────────

def test_console_channel_send(capsys):
    ch = ConsoleChannel()
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="login_success",
        username="alice",
        source_ip="185.220.101.34",
    )
    scored = ScoredEvent(
        event=ev,
        enrichment=None,
        score=75,
        reasons=["Suspicious IP"],
    )

    success = ch.send(scored)
    assert success is True

    captured = capsys.readouterr()
    assert "ALERT [score 75/100]" in captured.out
    assert "alice" in captured.out
    assert "185.220.101.34" in captured.out


@patch("output.alerts.requests.post")
def test_ntfy_channel_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    ch = NtfyChannel(topic="test-alerts", server="https://ntfy.sh")
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="login_success",
        username="alice",
        source_ip="185.220.101.34",
    )
    scored = ScoredEvent(
        event=ev,
        enrichment=None,
        score=90,
        reasons=["Critical ASN change"],
    )

    result = ch.send(scored)
    assert result is True

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert "https://ntfy.sh/test-alerts" in args
    assert kwargs["headers"]["Priority"] == "5"
    assert kwargs["headers"]["Tags"] == "rotating_light"
    assert "alice" in kwargs["headers"]["Title"]


@patch("output.alerts.requests.post")
def test_ntfy_channel_failure_graceful(mock_post):
    import requests
    mock_post.side_effect = requests.RequestException("Network down")

    ch = NtfyChannel(topic="test-alerts")
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="sudo_used",
        username="bob",
    )
    scored = ScoredEvent(
        event=ev,
        enrichment=None,
        score=50,
        reasons=["First sudo"],
    )

    result = ch.send(scored)
    assert result is False


@patch("output.alerts.requests.post")
def test_webhook_channel_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    ch = WebhookChannel(
        url="https://example.com/alerts",
        headers={"Authorization": "Bearer secret-token"},
    )
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="UNAUTHORIZED_KEY_ADD",
        username="attacker",
        source_ip="198.51.100.1",
    )
    scored = ScoredEvent(
        event=ev,
        severity="CRITICAL",
        score=95,
        reasons=["Unauthorized SSH key installed"],
        playbook="Remove unauthorized public key",
    )

    assert ch.send(scored) is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://example.com/alerts"
    assert kwargs["headers"]["Authorization"] == "Bearer secret-token"
    assert kwargs["headers"]["Content-Type"] == "application/json"
    assert kwargs["json"]["score"] == 95
    assert kwargs["json"]["event"]["username"] == "attacker"


@patch("output.alerts.requests.post")
def test_webhook_channel_failure(mock_post):
    mock_post.side_effect = requests.RequestException("Connection refused")
    ch = WebhookChannel(url="https://example.com/alerts")
    ev = AuthEvent(timestamp="2024-01-15T14:30:00", event_type="sudo_used", username="test")
    scored = ScoredEvent(event=ev, score=50)

    assert ch.send(scored) is False


@patch("output.alerts.requests.post")
def test_slack_webhook_channel_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    ch = SlackWebhookChannel(webhook_url="https://hooks.slack.com/services/T00/B00/X")
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="KILL_CHAIN_ESCALATION",
        username="mallory",
        source_ip="203.0.113.5",
    )
    scored = ScoredEvent(
        event=ev,
        severity="CRITICAL",
        score=90,
        reasons=["Multi-stage escalation detected"],
        playbook="Isolate host immediately",
    )

    assert ch.send(scored) is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://hooks.slack.com/services/T00/B00/X"
    payload = kwargs["json"]
    assert "mallory" in payload["text"]
    assert len(payload["attachments"]) == 1
    att = payload["attachments"][0]
    assert att["color"] == "#E01E5A"  # Red for critical
    assert any(f["title"] == "User" and "`mallory`" in f["value"] for f in att["fields"])
    assert "Isolate host immediately" in att["text"]


@patch("output.alerts.requests.post")
def test_slack_webhook_channel_failure(mock_post):
    mock_post.side_effect = requests.RequestException("Slack timeout")
    ch = SlackWebhookChannel(webhook_url="https://hooks.slack.com/test")
    ev = AuthEvent(timestamp="2024-01-15T14:30:00", event_type="login_success", username="user")
    scored = ScoredEvent(event=ev, score=10)

    assert ch.send(scored) is False


@patch("output.alerts.requests.post")
def test_discord_webhook_channel_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 204  # Discord standard webhook response
    mock_post.return_value = mock_resp

    ch = DiscordWebhookChannel(
        webhook_url="https://discord.com/api/webhooks/123/xyz",
        username="CustomCanary",
    )
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="SUSPICIOUS_SUDO",
        username="eve",
        source_ip="192.0.2.1",
    )
    scored = ScoredEvent(
        event=ev,
        severity="WARNING",
        score=65,
        reasons=["Unusual binary executed with sudo"],
        playbook="Check process tree",
    )

    assert ch.send(scored) is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://discord.com/api/webhooks/123/xyz"
    payload = kwargs["json"]
    assert payload["username"] == "CustomCanary"
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["color"] == 0xF1C40F  # Gold/Yellow for warning
    assert any(f["name"] == "User" and "`eve`" in f["value"] for f in embed["fields"])
    assert "Unusual binary executed" in embed["description"]


@patch("output.alerts.requests.post")
def test_discord_webhook_channel_failure(mock_post):
    mock_post.side_effect = requests.RequestException("Discord 500")
    ch = DiscordWebhookChannel(webhook_url="https://discord.com/api/webhooks/123/xyz")
    ev = AuthEvent(timestamp="2024-01-15T14:30:00", event_type="login_success", username="user")
    scored = ScoredEvent(event=ev, score=10)

    assert ch.send(scored) is False


def test_get_channels_factory():
    config_all = {
        "alerts": {
            "console": True,
            "ntfy": {
                "enabled": True,
                "topic": "custom-topic",
            },
            "webhook": {
                "enabled": True,
                "url": "https://example.com/hook",
            },
            "slack": {
                "enabled": True,
                "webhook_url": "https://hooks.slack.com/services/test",
            },
            "discord": {
                "enabled": True,
                "webhook_url": "https://discord.com/api/webhooks/test",
            },
        }
    }
    channels = get_channels(config_all)
    assert len(channels) == 5
    assert any(isinstance(c, ConsoleChannel) for c in channels)
    assert any(isinstance(c, NtfyChannel) for c in channels)
    assert any(isinstance(c, WebhookChannel) for c in channels)
    assert any(isinstance(c, SlackWebhookChannel) for c in channels)
    assert any(isinstance(c, DiscordWebhookChannel) for c in channels)

    config_console_only = {
        "alerts": {
            "console": True,
            "ntfy": {"enabled": False},
            "webhook": {"enabled": False},
            "slack": {"enabled": False},
            "discord": {"enabled": False},
        }
    }
    channels_c = get_channels(config_console_only)
    assert len(channels_c) == 1
    assert isinstance(channels_c[0], ConsoleChannel)


def test_server_status_and_routes(tmp_path):
    import threading
    from http.server import HTTPServer
    from output.server import AuthCanaryHandler

    # Set up mock report files in tmp_path
    html_file = tmp_path / "report.html"
    html_file.write_text("<!DOCTYPE html><html><body><h1>Test Dashboard</h1></body></html>", encoding="utf-8")
    json_file = tmp_path / "report.json"
    json_file.write_text('{"status": "ok", "anomalies": 0}', encoding="utf-8")

    AuthCanaryHandler.output_dir = tmp_path

    # Start ephemeral server
    server = HTTPServer(("127.0.0.1", 0), AuthCanaryHandler)
    port = server.server_port

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    try:
        # Test /api/status
        res_status = requests.get(f"{base_url}/api/status")
        assert res_status.status_code == 200
        data = res_status.json()
        assert data["status"] == "online"
        assert data["report_exists"] is True

        # Test / (index)
        res_root = requests.get(f"{base_url}/")
        assert res_root.status_code == 200
        assert "Test Dashboard" in res_root.text
        assert "AuthCanary Live Refresh Hook" in res_root.text

        # Test /report.json
        res_json = requests.get(f"{base_url}/report.json")
        assert res_json.status_code == 200
        assert res_json.json()["status"] == "ok"

        # Test 404
        res_404 = requests.get(f"{base_url}/nonexistent")
        assert res_404.status_code == 404
    finally:
        server.shutdown()
        server.server_close()

