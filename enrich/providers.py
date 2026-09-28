"""
AuthCanary — IP enrichment providers.

Resolves source IPs to ASN, org, and rough geolocation using free APIs.
Pluggable: implement IPEnrichmentProvider to swap in a paid provider
without touching any other module.
"""

from __future__ import annotations

import ipaddress
import time
from abc import ABC, abstractmethod

import requests

from engine.models import EnrichmentResult


class IPEnrichmentProvider(ABC):
    """Interface for IP-to-ASN/geo resolution."""

    @abstractmethod
    def enrich(self, ip: str) -> EnrichmentResult:
        """Look up enrichment data for a single IP address."""
        ...


class IpApiProvider(IPEnrichmentProvider):
    """Free enrichment via ip-api.com (no API key required).

    Rate limit: 45 requests/minute on the free tier.
    Graceful degradation: returns an unenriched result on any failure.
    """

    BASE_URL = "http://ip-api.com/json"
    FIELDS = "status,message,country,city,lat,lon,isp,org,as,query"

    def __init__(self, rate_limit_per_min: int = 45) -> None:
        self._min_interval = 60.0 / rate_limit_per_min
        self._last_request: float = 0.0

    def enrich(self, ip: str) -> EnrichmentResult:
        # Skip private / loopback IPs
        if self._is_private(ip):
            return EnrichmentResult(
                ip=ip, asn="private", org="private",
                country="local", city="local", enriched=False,
            )

        self._throttle()

        try:
            resp = requests.get(
                f"{self.BASE_URL}/{ip}",
                params={"fields": self.FIELDS},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError):
            # Network down, timeout, bad JSON — degrade gracefully
            return EnrichmentResult(ip=ip, enriched=False)

        if data.get("status") != "success":
            return EnrichmentResult(ip=ip, enriched=False)

        return EnrichmentResult(
            ip=ip,
            asn=data.get("as", "unknown"),
            org=data.get("org", data.get("isp", "unknown")),
            country=data.get("country", "unknown"),
            city=data.get("city", "unknown"),
            lat=float(data.get("lat", 0.0)),
            lon=float(data.get("lon", 0.0)),
            enriched=True,
        )

    def _throttle(self) -> None:
        """Respect the 45 req/min rate limit with a simple sleep."""
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check for RFC 1918 / loopback / link-local addresses."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False


def get_provider(provider_name: str, **kwargs) -> IPEnrichmentProvider:
    """Factory — currently only ip-api is implemented."""
    providers = {
        "ip-api": IpApiProvider,
    }
    cls = providers.get(provider_name)
    if cls is None:
        raise ValueError(
            f"Unknown enrichment provider: {provider_name!r}. "
            f"Available: {', '.join(providers)}"
        )
    return cls(**kwargs)
