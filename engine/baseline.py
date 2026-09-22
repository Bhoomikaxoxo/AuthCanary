"""
AuthCanary — Baseline storage and warm-up logic.

Manages SQLite tables that track "what's normal" for each user:
  - Login-hour histogram (0–23)
  - Seen IPs, ASNs, SSH key fingerprints
  - Sudo users
  - Warm-up state

All tables live in a single SQLite file (zero-config, no server).
"""

from __future__ import annotations

import json
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

                CREATE TABLE IF NOT EXISTS seen_sudo_commands (
                    username    TEXT,
                    command     TEXT,
                    first_seen  TEXT,
                    count       INTEGER DEFAULT 1,
                    PRIMARY KEY (username, command)
                );

                CREATE TABLE IF NOT EXISTS seen_binaries (
                    username    TEXT,
                    binary_path TEXT,
                    first_seen  TEXT,
                    count       INTEGER DEFAULT 1,
                    PRIMARY KEY (username, binary_path)
                );

                CREATE TABLE IF NOT EXISTS seen_persistence (
                    target_path TEXT,
                    label       TEXT,
                    hash        TEXT,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    PRIMARY KEY (target_path, hash)
                );

                CREATE TABLE IF NOT EXISTS seen_tcc_grants (
                    service     TEXT,
                    client_id   TEXT,
                    first_seen  TEXT,
                    PRIMARY KEY (service, client_id)
                );

                CREATE TABLE IF NOT EXISTS event_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    event_type  TEXT,
                    username    TEXT,
                    source_ip   TEXT,
                    score       INTEGER,
                    reasons     TEXT,
                    raw_line    TEXT,
                    signals_json TEXT DEFAULT '[]',
                    severity    TEXT DEFAULT 'INFO',
                    invariants_json TEXT DEFAULT '[]',
                    process     TEXT DEFAULT 'system',
                    is_novel    INTEGER DEFAULT 0,
                    command     TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS file_integrity_hashes (
                    filepath     TEXT PRIMARY KEY,
                    sha256       TEXT,
                    mtime        REAL,
                    size         INTEGER,
                    last_checked TEXT,
                    status       TEXT
                );

                CREATE TABLE IF NOT EXISTS alert_feedback (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    username           TEXT,
                    signal             TEXT,
                    marked_benign_at   TEXT,
                    admin_user         TEXT,
                    notes              TEXT
                );

                CREATE TABLE IF NOT EXISTS warmup_state (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    start_date      TEXT,
                    events_processed INTEGER DEFAULT 0,
                    warmup_complete INTEGER DEFAULT 0
                );
            """)

            # Dynamic migrations: ensure event_log has all modern columns
            cursor = conn.execute("PRAGMA table_info(event_log)")
            columns = [row[1] for row in cursor.fetchall()]
            for col_name, col_def in [
                ("signals_json", "TEXT DEFAULT '[]'"),
                ("severity", "TEXT DEFAULT 'INFO'"),
                ("invariants_json", "TEXT DEFAULT '[]'"),
                ("process", "TEXT DEFAULT 'system'"),
                ("is_novel", "INTEGER DEFAULT 0"),
                ("command", "TEXT DEFAULT ''"),
            ]:
                if col_name not in columns:
                    conn.execute(f"ALTER TABLE event_log ADD COLUMN {col_name} {col_def}")

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

    def get_warmup_info(self) -> dict:
        """Structured warm-up progress data for dashboards and reporters."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT start_date, events_processed, warmup_complete "
                "FROM warmup_state WHERE id = 1"
            ).fetchone()

        if row is None:
            return {
                "warmup_complete": False,
                "days_elapsed": 0,
                "days_total": self.warmup_days,
                "days_left": self.warmup_days,
                "events_processed": 0,
                "min_events": self.warmup_min_events,
                "events_left": self.warmup_min_events,
                "event_quota_met": False,
                "time_quota_met": False,
            }

        start = datetime.fromisoformat(row[0])
        days_elapsed = (datetime.now() - start).days
        events = row[1]
        is_complete = bool(row[2]) or (days_elapsed >= self.warmup_days and events >= self.warmup_min_events)
        event_quota_met = events >= self.warmup_min_events
        time_quota_met = days_elapsed >= self.warmup_days
        days_left = max(0, self.warmup_days - days_elapsed)
        events_left = max(0, self.warmup_min_events - events)

        return {
            "warmup_complete": is_complete,
            "days_elapsed": days_elapsed,
            "days_total": self.warmup_days,
            "days_left": days_left,
            "events_processed": events,
            "min_events": self.warmup_min_events,
            "events_left": events_left,
            "event_quota_met": event_quota_met,
            "time_quota_met": time_quota_met,
        }

    def warmup_status(self) -> str:
        """Human-readable warm-up progress message."""
        info = self.get_warmup_info()
        if info["warmup_complete"]:
            return "✓ Baseline warm-up complete. Alerting is active."

        if info["event_quota_met"]:
            return (
                f"Event quota met ({info['events_processed']}/{info['min_events']}) · "
                f"Day {info['days_elapsed']}/{info['days_total']} time-based warm-up still active."
            )

        return (
            f"⏳ Warm-up: Day {info['days_elapsed']}/{info['days_total']}, "
            f"{info['events_processed']}/{info['min_events']} events processed. "
            f"Learning baseline, not alerting yet. "
            f"({info['days_left']} days, {info['events_left']} events remaining)"
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

    def is_sudo_command_known(self, username: str, command: str) -> bool:
        """Check if this user has previously executed this specific sudo command."""
        if not command:
            return True
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_sudo_commands WHERE username = ? AND command = ?",
                (username, command),
            ).fetchone()
        return row is not None

    def record_sudo_command(self, username: str, command: str) -> None:
        """Record a sudo command in the baseline ledger."""
        if not command:
            return
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO seen_sudo_commands (username, command, first_seen, count) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(username, command) DO UPDATE SET count = count + 1",
                (username, command, now),
            )

    def is_binary_known(self, username: str, binary_path: str) -> bool:
        """Check if this user has previously executed this binary."""
        if not binary_path:
            return True
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_binaries WHERE username = ? AND binary_path = ?",
                (username, binary_path),
            ).fetchone()
        return row is not None

    def record_binary(self, username: str, binary_path: str, ts: str | None = None) -> None:
        """Record a binary execution in the baseline."""
        if not binary_path:
            return
        now = ts or datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO seen_binaries (username, binary_path, first_seen, count) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(username, binary_path) DO UPDATE SET count = count + 1",
                (username, binary_path, now),
            )

    def is_persistence_known(self, target_path: str, hash_val: str) -> bool:
        """Check if this persistence target file hash is already known."""
        if not target_path or not hash_val:
            return True
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_persistence WHERE target_path = ? AND hash = ?",
                (target_path, hash_val),
            ).fetchone()
        return row is not None

    def record_persistence(self, target_path: str, label: str, hash_val: str, ts: str | None = None) -> None:
        """Record or update a persistence item in the baseline."""
        if not target_path or not hash_val:
            return
        now = ts or datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO seen_persistence (target_path, label, hash, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(target_path, hash) DO UPDATE SET last_seen = ?",
                (target_path, label, hash_val, now, now, now),
            )

    def is_tcc_grant_known(self, service: str, client_id: str) -> bool:
        """Check if this TCC permission grant has been seen before."""
        if not service or not client_id:
            return True
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_tcc_grants WHERE service = ? AND client_id = ?",
                (service, client_id),
            ).fetchone()
        return row is not None

    def record_tcc_grant(self, service: str, client_id: str, ts: str | None = None) -> None:
        """Record a TCC permission grant in the baseline."""
        if not service or not client_id:
            return
        now = ts or datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO seen_tcc_grants (service, client_id, first_seen) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(service, client_id) DO NOTHING",
                (service, client_id, now),
            )

    def get_process_stats(self) -> dict[str, dict]:
        """Return event count, warning count, and critical count by process."""
        stats: dict[str, dict] = {}
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT COALESCE(process, 'system') as proc, severity, COUNT(*) as cnt "
                "FROM event_log GROUP BY proc, severity"
            ).fetchall()
        for r in rows:
            proc = r["proc"] or "system"
            if proc not in stats:
                stats[proc] = {"count": 0, "warnings": 0, "critical": 0}
            cnt = r["cnt"]
            stats[proc]["count"] += cnt
            if r["severity"] in ("WARNING", "CRITICAL"):
                stats[proc]["warnings"] += cnt
            if r["severity"] == "CRITICAL":
                stats[proc]["critical"] += cnt
        return stats

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

    def get_recent_user_events(
        self,
        username: str,
        window_minutes: int,
        current_timestamp: str | None = None,
    ) -> list[dict]:
        """Fetch user events within the rolling window prior to current_timestamp."""
        if not current_timestamp:
            current_time = datetime.now()
        else:
            try:
                current_time = datetime.fromisoformat(current_timestamp)
            except ValueError:
                current_time = datetime.now()

        since = (current_time - timedelta(minutes=window_minutes)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, event_type, username, source_ip, score, reasons, signals_json "
                "FROM event_log "
                "WHERE username = ? AND timestamp >= ? AND timestamp <= ? "
                "ORDER BY timestamp ASC",
                (username, since, current_time.isoformat()),
            ).fetchall()

        results = []
        for r in rows:
            try:
                sig_list = json.loads(r["signals_json"]) if r["signals_json"] else []
            except (json.JSONDecodeError, TypeError):
                sig_list = []
            results.append({
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "username": r["username"],
                "source_ip": r["source_ip"],
                "score": r["score"],
                "reasons": r["reasons"],
                "signals": sig_list,
            })
        return results

    def get_all_logged_events(self, limit: int = 1000) -> list[dict]:
        """Fetch all logged events from event_log ordered by timestamp DESC."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, event_type, username, source_ip, score, reasons, raw_line, "
                "signals_json, severity, invariants_json, process, is_novel, command "
                "FROM event_log "
                "ORDER BY timestamp DESC, id DESC "
                "LIMIT ?",
                (limit,),
            ).fetchall()

        results = []
        for r in rows:
            try:
                sig_list = json.loads(r["signals_json"]) if r["signals_json"] else []
            except (json.JSONDecodeError, TypeError):
                sig_list = []
            try:
                inv_list = json.loads(r["invariants_json"]) if r["invariants_json"] else []
            except (json.JSONDecodeError, TypeError):
                inv_list = []
            reasons_list = [s.strip() for s in r["reasons"].split(";")] if r["reasons"] else []
            results.append({
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "username": r["username"],
                "source_ip": r["source_ip"],
                "score": r["score"],
                "reasons": reasons_list,
                "raw_line": r["raw_line"] or "",
                "signals": sig_list,
                "severity": r["severity"] or "INFO",
                "invariants": inv_list,
                "process": r["process"] or "system",
                "is_novel": bool(r["is_novel"]),
                "command": r["command"] or "",
            })
        return results

    # ── Updates (after scoring, update the baseline) ───────────────

    def record_event(self, event: AuthEvent,
                     enrichment: EnrichmentResult | None = None,
                     score: int = 0,
                     reasons: list[str] | None = None,
                     signals: list[str] | None = None,
                     severity: str = "INFO",
                     invariants: list[str] | None = None,
                     is_novel: bool = False,
                     command: str = "",
                     process: str = "") -> None:
        """Record a processed event and update all baseline tables."""
        now = datetime.now().isoformat()
        signals_str = json.dumps(signals or [])
        invariants_str = json.dumps(invariants or [])
        effective_cmd = command or getattr(event, "command", "") or ""
        effective_proc = process or getattr(event, "process", "") or "system"
        reasons_list = reasons or []

        with sqlite3.connect(self.db_path) as conn:
            # Log the event with structured signals and invariants
            conn.execute(
                "INSERT INTO event_log "
                "(timestamp, event_type, username, source_ip, score, reasons, raw_line, "
                "signals_json, severity, invariants_json, process, is_novel, command) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event.timestamp, event.event_type, event.username,
                 event.source_ip, score, "; ".join(reasons_list), event.raw_line,
                 signals_str, severity, invariants_str, effective_proc, int(is_novel), effective_cmd),
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
                fp = self._extract_fingerprint(event.raw_line)
                if fp:
                    conn.execute(
                        "INSERT OR IGNORE INTO seen_ssh_keys "
                        "(username, fingerprint, first_seen) VALUES (?, ?, ?)",
                        (event.username, fp, now),
                    )

            # Update sudo users and commands
            if event.event_type in ("sudo_used", "privilege_elevation") or effective_proc == "sudo":
                conn.execute(
                    "INSERT INTO sudo_users (username, first_seen, count) "
                    "VALUES (?, ?, 1) "
                    "ON CONFLICT(username) DO UPDATE SET count = count + 1",
                    (event.username, now),
                )
                if effective_cmd:
                    conn.execute(
                        "INSERT INTO seen_sudo_commands (username, command, first_seen, count) "
                        "VALUES (?, ?, ?, 1) "
                        "ON CONFLICT(username, command) DO UPDATE SET count = count + 1",
                        (event.username, effective_cmd, now),
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
