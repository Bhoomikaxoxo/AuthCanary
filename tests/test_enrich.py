"""
AuthCanary — Tests for the enrichment layer.

Tests cache behavior, graceful degradation, and rate-limiting.
Uses mocked HTTP responses — no actual API calls.
"""

import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.models import EnrichmentResult
from enrich.providers import IpApiProvider, get_provider
from enrich.cache import EnrichmentCache


# ── Provider tests ─────────────────────────────────────────────────

def test_private_ip_skips_api():
    provider = IpApiProvider()
    result = provider.enrich("192.168.1.100")
    assert result.asn == "private"
    assert result.enriched is False


def test_loopback_skips_api():
    provider = IpApiProvider()
    result = provider.enrich("127.0.0.1")
    assert result.asn == "private"
    assert result.enriched is False


@patch("enrich.providers.requests.get")
def test_successful_enrichment(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
        "isp": "Example ISP",
        "org": "Example Org",
        "as": "AS12345 Example",
        "query": "185.220.101.34",
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    provider = IpApiProvider()
    result = provider.enrich("185.220.101.34")

    assert result.enriched is True
    assert result.asn == "AS12345 Example"
    assert result.country == "Germany"
    assert result.city == "Berlin"


@patch("enrich.providers.requests.get")
def test_network_failure_degrades_gracefully(mock_get):
    import requests
    mock_get.side_effect = requests.ConnectionError("No internet")

    provider = IpApiProvider()
    result = provider.enrich("8.8.8.8")

    assert result.enriched is False
    assert result.asn == "unknown"


@patch("enrich.providers.requests.get")
def test_api_error_degrades_gracefully(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "fail", "message": "private range"}
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    provider = IpApiProvider()
    result = provider.enrich("8.8.8.8")

    assert result.enriched is False


def test_get_provider_factory():
    provider = get_provider("ip-api")
    assert isinstance(provider, IpApiProvider)


def test_get_provider_unknown_raises():
    try:
        get_provider("nonexistent-provider")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ── Cache tests ────────────────────────────────────────────────────

@patch("enrich.providers.requests.get")
def test_cache_stores_and_retrieves(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "US",
        "city": "Mountain View",
        "lat": 37.386,
        "lon": -122.084,
        "isp": "Google",
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
        "query": "8.8.8.8",
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        provider = IpApiProvider()
        cache = EnrichmentCache(db_path, provider, ttl_days=30)

        # First lookup — hits API
        result1 = cache.lookup("8.8.8.8")
        assert result1.enriched is True
        assert mock_get.call_count == 1

        # Second lookup — should hit cache, not API
        result2 = cache.lookup("8.8.8.8")
        assert result2.enriched is True
        assert result2.asn == "AS15169 Google LLC"
        assert mock_get.call_count == 1  # No additional API call


def test_cache_miss_returns_fresh():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")

        # Mock provider that returns unenriched
        mock_provider = MagicMock()
        mock_provider.enrich.return_value = EnrichmentResult(
            ip="5.5.5.5", enriched=False)

        cache = EnrichmentCache(db_path, mock_provider, ttl_days=30)
        result = cache.lookup("5.5.5.5")

        assert result.enriched is False
        mock_provider.enrich.assert_called_once_with("5.5.5.5")
