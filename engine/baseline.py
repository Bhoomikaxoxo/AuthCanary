"""
SentinelLog — Baseline storage and warm-up logic.

Manages SQLite tables that track "what's normal" for each user:
  - Login-hour histogram (0–23)
  - Seen IPs, ASNs, SSH key fingerprints
  - Sudo users
  - Warm-up state

All tables live in a single SQLite file (zero-config, no server).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult


class Baseline:
    """Per-user behavioral baseline backed by SQLite."""

    def __init__(self, db_path: str, warmup_days: int = 7,
                 warmup_min_events: int = 50) -> None:
        self.db_path = str(Path(db_path).expanduser())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.warmup_days = warmup_days
        self.warmup_min_events = warmup_min_events
        self._init_db()

    # ── Schema setup ───────────────────────────────────────────────

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS login_hour_histogram (
                    username TEXT PRIMARY KEY,
                    h0  INTEGER DEFAULT 0, h1  INTEGER DEFAULT 0,
                    h2  INTEGER DEFAULT 0, h3  INTEGER DEFAULT 0,
                    h4  INTEGER DEFAULT 0, h5  INTEGER DEFAULT 0,
                    h6  INTEGER DEFAULT 0, h7  INTEGER DEFAULT 0,
                    h8  INTEGER DEFAULT 0, h9  INTEGER DEFAULT 0,
                    h10 INTEGER DEFAULT 0, h11 INTEGER DEFAULT 0,
                    h12 INTEGER DEFAULT 0, h13 INTEGER DEFAULT 0,
                    h14 INTEGER DEFAULT 0, h15 INTEGER DEFAULT 0,
                    h16 INTEGER DEFAULT 0, h17 INTEGER DEFAULT 0,
                    h18 INTEGER DEFAULT 0, h19 INTEGER DEFAULT 0,
                    h20 INTEGER DEFAULT 0, h21 INTEGER DEFAULT 0,
                    h22 INTEGER DEFAULT 0, h23 INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS seen_ips (
                    username    TEXT,
                    ip          TEXT,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    count       INTEGER DEFAULT 1,
                    PRIMARY KEY (username, ip)
                );

                CREATE TABLE IF NOT EXISTS seen_asns (
                    username    TEXT,
                    asn         TEXT,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    count       INTEGER DEFAULT 1,
                    PRIMARY KEY (username, asn)
                );

                CREATE TABLE IF NOT EXISTS seen_ssh_keys (
                    username    TEXT,
                    fingerprint TEXT,
                    first_seen  TEXT,
                    PRIMARY KEY (username, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS sudo_users (
                    username    TEXT PRIMARY KEY,
                    first_seen  TEXT,
                    count       INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS event_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    event_type  TEXT,
                    username    TEXT,
                    source_ip   TEXT,
                    score       INTEGER,
                    reasons     TEXT,
                    raw_line    TEXT
                );

                CREATE TABLE IF NOT EXISTS warmup_state (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    start_date      TEXT,
                    events_processed INTEGER DEFAULT 0,
                    warmup_complete INTEGER DEFAULT 0
                );
            """)

            # Ensure warmup_state has a row
            row = conn.execute("SELECT id FROM warmup_state").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO warmup_state (id, start_date, events_processed) "
                    "VALUES (1, ?, 0)",
                    (datetime.now().isoformat(),),
                )

    # ── Warm-up ────────────────────────────────────────────────────

    def is_warmed_up(self) -> bool:
        """Both conditions (days AND events) must be met."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT start_date, events_processed, warmup_complete "
                "FROM warmup_state WHERE id = 1"
            ).fetchone()

        if row is None:
            return False
        if row[2]:  # Already marked complete
            return True

        start = datetime.fromisoformat(row[0])
        days_elapsed = (datetime.now() - start).days
        events = row[1]

        if days_elapsed >= self.warmup_days and events >= self.warmup_min_events:
            # Mark as complete so we don't recompute
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE warmup_state SET warmup_complete = 1 WHERE id = 1")
            return True
        return False

    def warmup_status(self) -> str:
        """Human-readable warm-up progress message."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT start_date, events_processed, warmup_complete "
                "FROM warmup_state WHERE id = 1"
            ).fetchone()

        if row is None or row[2]:
            return "✓ Baseline warm-up complete. Alerting is active."

        start = datetime.fromisoformat(row[0])
        days_elapsed = (datetime.now() - start).days
        events = row[1]
        days_left = max(0, self.warmup_days - days_elapsed)
        events_left = max(0, self.warmup_min_events - events)

        return (
            f"⏳ Warm-up: Day {days_elapsed}/{self.warmup_days}, "
            f"{events}/{self.warmup_min_events} events processed. "
            f"Learning baseline, not alerting yet. "
            f"({days_left} days, {events_left} events remaining)"
        )

    def increment_event_count(self, n: int = 1) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE warmup_state SET events_processed = events_processed + ? "
                "WHERE id = 1",
                (n,),
            )

    # ── Queries (used by scoring) ──────────────────────────────────

    def is_ip_known(self, username: str, ip: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_ips WHERE username = ? AND ip = ?",
                (username, ip),
            ).fetchone()
        return row is not None

    def is_asn_known(self, username: str, asn: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_asns WHERE username = ? AND asn = ?",
                (username, asn),
            ).fetchone()
        return row is not None

    def is_ssh_key_known(self, username: str, fingerprint: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_ssh_keys WHERE username = ? AND fingerprint = ?",
                (username, fingerprint),
            ).fetchone()
        return row is not None

    def is_sudo_user_known(self, username: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sudo_users WHERE username = ?",
                (username,),
            ).fetchone()
        return row is not None

    def get_hour_histogram(self, username: str) -> list[int]:
        """Return 24-element list of login counts per hour for this user."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,"
                "h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23 "
                "FROM login_hour_histogram WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return [0] * 24
        return list(row)

    def get_recent_failures(self, username: str, ip: str,
                            since: str) -> int:
        """Count login_failure events from this IP since the given timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM event_log "
                "WHERE username = ? AND source_ip = ? "
                "AND event_type = 'login_failure' AND timestamp >= ?",
                (username, ip, since),
            ).fetchone()
        return row[0] if row else 0

    # ── Updates (after scoring, update the baseline) ───────────────

    def record_event(self, event: AuthEvent,
                     enrichment: EnrichmentResult | None,
                     score: int, reasons: list[str]) -> None:
        """Record a processed event and update all baseline tables."""
        now = datetime.now().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Log the event
            conn.execute(
                "INSERT INTO event_log "
                "(timestamp, event_type, username, source_ip, score, reasons, raw_line) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event.timestamp, event.event_type, event.username,
                 event.source_ip, score, "; ".join(reasons), event.raw_line),
            )

            # Update hour histogram for logins
            if event.event_type in ("login_success", "login_failure"):
                try:
                    hour = datetime.fromisoformat(event.timestamp).hour
                except ValueError:
                    hour = 0
                col = f"h{hour}"
                conn.execute(
                    f"INSERT INTO login_hour_histogram (username, {col}) "
                    f"VALUES (?, 1) "
                    f"ON CONFLICT(username) DO UPDATE SET {col} = {col} + 1",
                    (event.username,),
                )

            # Update seen IPs
            if event.source_ip:
                conn.execute(
                    "INSERT INTO seen_ips (username, ip, first_seen, last_seen, count) "
                    "VALUES (?, ?, ?, ?, 1) "
                    "ON CONFLICT(username, ip) DO UPDATE SET "
                    "last_seen = ?, count = count + 1",
                    (event.username, event.source_ip, now, now, now),
                )

            # Update seen ASNs
            if enrichment and enrichment.asn not in ("unknown", "private"):
                conn.execute(
                    "INSERT INTO seen_asns (username, asn, first_seen, last_seen, count) "
                    "VALUES (?, ?, ?, ?, 1) "
                    "ON CONFLICT(username, asn) DO UPDATE SET "
                    "last_seen = ?, count = count + 1",
                    (event.username, enrichment.asn, now, now, now),
                )

            # Update SSH keys
            if event.event_type == "ssh_key_added":
                # Extract fingerprint from raw line if available
                fp = self._extract_fingerprint(event.raw_line)
                if fp:
                    conn.execute(
                        "INSERT OR IGNORE INTO seen_ssh_keys "
                        "(username, fingerprint, first_seen) VALUES (?, ?, ?)",
                        (event.username, fp, now),
                    )

            # Update sudo users
            if event.event_type == "sudo_used":
                conn.execute(
                    "INSERT INTO sudo_users (username, first_seen, count) "
                    "VALUES (?, ?, 1) "
                    "ON CONFLICT(username) DO UPDATE SET count = count + 1",
                    (event.username, now),
                )

        self.increment_event_count()

    def get_stats(self) -> dict:
        """Return summary statistics for the report."""
        with sqlite3.connect(self.db_path) as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) FROM event_log").fetchone()[0]
            unique_users = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM event_log").fetchone()[0]
            unique_ips = conn.execute(
                "SELECT COUNT(DISTINCT ip) FROM seen_ips").fetchone()[0]
            unique_asns = conn.execute(
                "SELECT COUNT(DISTINCT asn) FROM seen_asns").fetchone()[0]
            warmup_row = conn.execute(
                "SELECT warmup_complete FROM warmup_state WHERE id = 1"
            ).fetchone()
        return {
            "total_events": total_events,
            "unique_users": unique_users,
            "unique_ips": unique_ips,
            "unique_asns": unique_asns,
            "warmup_complete": bool(warmup_row[0]) if warmup_row else False,
        }

    def reset(self) -> None:
        """Wipe all baseline data — forces full relearning."""
        with sqlite3.connect(self.db_path) as conn:
            for table in ("login_hour_histogram", "seen_ips", "seen_asns",
                          "seen_ssh_keys", "sudo_users", "event_log",
                          "warmup_state"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute(
                "INSERT INTO warmup_state (id, start_date, events_processed) "
                "VALUES (1, ?, 0)",
                (datetime.now().isoformat(),),
            )

    @staticmethod
    def _extract_fingerprint(raw_line: str) -> str:
        """Best-effort fingerprint extraction from a raw log line."""
        import re
        m = re.search(r"(?:SHA256:|fingerprint\s+)(\S+)", raw_line)
        return m.group(1) if m else ""
