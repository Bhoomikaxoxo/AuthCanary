"""
SentinelLog — IP enrichment cache.

SQLite-backed cache so repeated IPs don't re-hit the API.
Lives in the same database as the baseline tables.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from engine.models import EnrichmentResult
from enrich.providers import IPEnrichmentProvider


class EnrichmentCache:
    """Cache IP enrichment results in SQLite with TTL-based expiry."""

    def __init__(self, db_path: str, provider: IPEnrichmentProvider,
                 ttl_days: int = 30) -> None:
        self.db_path = db_path
        self.provider = provider
        self.ttl = timedelta(days=ttl_days)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip          TEXT PRIMARY KEY,
                    asn         TEXT,
                    org         TEXT,
                    country     TEXT,
                    city        TEXT,
                    lat         REAL,
                    lon         REAL,
                    fetched_at  TEXT
                )
            """)

    def lookup(self, ip: str) -> EnrichmentResult:
        """Return cached result if fresh, otherwise fetch and cache."""
        cached = self._get_cached(ip)
        if cached is not None:
            return cached

        # Cache miss or stale — fetch from provider
        result = self.provider.enrich(ip)
        if result.enriched:
            self._store(result)
        return result

    def _get_cached(self, ip: str) -> EnrichmentResult | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT asn, org, country, city, lat, lon, fetched_at "
                "FROM ip_cache WHERE ip = ?",
                (ip,),
            ).fetchone()

        if row is None:
            return None

        fetched_at = datetime.fromisoformat(row[6])
        if datetime.now() - fetched_at > self.ttl:
            return None  # Stale — re-fetch

        return EnrichmentResult(
            ip=ip,
            asn=row[0], org=row[1], country=row[2], city=row[3],
            lat=row[4], lon=row[5],
            enriched=True,
        )

    def _store(self, result: EnrichmentResult) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ip_cache "
                "(ip, asn, org, country, city, lat, lon, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (result.ip, result.asn, result.org, result.country,
                 result.city, result.lat, result.lon,
                 datetime.now().isoformat()),
            )
