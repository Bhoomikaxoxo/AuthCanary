"""
SentinelLog — Tests for the output layer.

Tests report generation (JSON + HTML dashboard) and alert delivery channels
(ConsoleChannel and NtfyChannel with mocked HTTP).
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult, ScoredEvent
from engine.baseline import Baseline
from output.report import generate_report
from output.alerts import ConsoleChannel, NtfyChannel, get_channels


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


def test_get_channels_factory():
    config_all = {
        "alerts": {
            "console": True,
            "ntfy": {
                "enabled": True,
                "topic": "custom-topic",
            },
        }
    }
    channels = get_channels(config_all)
    assert len(channels) == 2
    assert any(isinstance(c, ConsoleChannel) for c in channels)
    assert any(isinstance(c, NtfyChannel) for c in channels)

    config_console_only = {
        "alerts": {
            "console": True,
            "ntfy": {"enabled": False},
        }
    }
    channels_c = get_channels(config_console_only)
    assert len(channels_c) == 1
    assert isinstance(channels_c[0], ConsoleChannel)
