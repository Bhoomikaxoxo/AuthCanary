"""
AuthCanary — Tests for the engine layer.

Tests baseline persistence, warm-up tracking, statistics calculation,
and the invariant engine (severity classification, signals, and thresholds).
"""

import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult, ScoredEvent
from engine.baseline import Baseline
from engine.invariants import InvariantEngine
from engine.novelty import NoveltyTracker


# ── Baseline tests ──────────────────────────────────────────────────

def test_baseline_init_and_tables():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name, warmup_days=7, warmup_min_events=50)
        assert Path(tmp.name).exists()

        with sqlite3.connect(tmp.name) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        expected = {
            "login_hour_histogram",
            "seen_ips",
            "seen_asns",
            "seen_ssh_keys",
            "sudo_users",
            "event_log",
            "warmup_state",
        }
        assert expected.issubset(tables)


def test_baseline_record_event_updates_state():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        assert not b.is_ip_known("alice", "1.2.3.4")
        assert not b.is_asn_known("alice", "AS12345")
        assert not b.is_sudo_user_known("alice")

        ev_login = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="1.2.3.4",
            auth_method="password",
        )
        enr = EnrichmentResult(ip="1.2.3.4", asn="AS12345", org="Example ISP", enriched=True)
        b.record_event(ev_login, enr, score=0, reasons=[])

        assert b.is_ip_known("alice", "1.2.3.4")
        assert b.is_asn_known("alice", "AS12345")
        assert not b.is_ip_known("bob", "1.2.3.4")

        # Check histogram
        hist = b.get_hour_histogram("alice")
        assert hist[14] == 1
        assert hist[0] == 0

        # Sudo record
        ev_sudo = AuthEvent(
            timestamp="2024-01-15T14:35:00",
            event_type="sudo_used",
            username="alice",
        )
        b.record_event(ev_sudo, None, score=0, reasons=[])
        assert b.is_sudo_user_known("alice")
        assert not b.is_sudo_user_known("bob")

        # SSH key record
        ev_key = AuthEvent(
            timestamp="2024-01-15T14:40:00",
            event_type="ssh_key_added",
            username="deploy",
            raw_line="sshd[123]: key added: SHA256:fingerprint123 for user deploy added",
        )
        b.record_event(ev_key, None, score=0, reasons=[])
        assert b.is_ssh_key_known("deploy", "fingerprint123")


def test_baseline_warmup_status():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name, warmup_days=7, warmup_min_events=10)
        assert not b.is_warmed_up()
        status = b.warmup_status()
        assert "Warm-up" in status
        assert "not alerting yet" in status

        # Advance events
        b.increment_event_count(15)

        # Still need 7 days by default unless start_date is set in past
        with sqlite3.connect(tmp.name) as conn:
            past_date = (datetime.now() - timedelta(days=8)).isoformat()
            conn.execute("UPDATE warmup_state SET start_date = ? WHERE id = 1", (past_date,))

        assert b.is_warmed_up()
        assert "warm-up complete" in b.warmup_status().lower()


def test_baseline_stats():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="1.2.3.4",
        )
        enr = EnrichmentResult(ip="1.2.3.4", asn="AS12345", enriched=True)
        b.record_event(ev, enr, score=0, reasons=[])

        stats = b.get_stats()
        assert stats["total_events"] == 1
        assert stats["unique_users"] == 1
        assert stats["unique_ips"] == 1
        assert stats["unique_asns"] == 1


def test_baseline_reset():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="1.2.3.4",
        )
        b.record_event(ev, None, score=0, reasons=[])
        assert b.is_ip_known("alice", "1.2.3.4")

        b.reset()
        assert not b.is_ip_known("alice", "1.2.3.4")
        assert b.get_stats()["total_events"] == 0


# ── InvariantEngine + NoveltyTracker tests ─────────────────────────

def test_clean_known_event():
    """A repeat event from a known IP/ASN should score 0 with INFO severity."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        ev_prev = AuthEvent(
            timestamp="2024-01-15T14:00:00",
            event_type="login_success",
            username="alice",
            source_ip="8.8.8.8",
            auth_method="password",
        )
        enr_prev = EnrichmentResult(ip="8.8.8.8", asn="AS15169", org="Google", enriched=True)
        b.record_event(ev_prev, enr_prev, 0, [])

        engine = InvariantEngine()
        tracker = NoveltyTracker()

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="8.8.8.8",
            auth_method="password",
        )
        enr = EnrichmentResult(ip="8.8.8.8", asn="AS15169", org="Google", enriched=True)

        is_novel, novelty_reasons = tracker.evaluate(ev, enr, b)
        scored = engine.evaluate(ev, enr, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.score == 0
        assert scored.severity == "INFO"


def test_new_ip_new_asn():
    """A login from a never-seen IP and ASN should flag as novel."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        ev_prev = AuthEvent(
            timestamp="2024-01-15T14:00:00",
            event_type="login_success",
            username="alice",
            source_ip="8.8.8.8",
            auth_method="password",
        )
        enr_prev = EnrichmentResult(ip="8.8.8.8", asn="AS15169", org="Google", enriched=True)
        b.record_event(ev_prev, enr_prev, 0, [])

        engine = InvariantEngine()
        tracker = NoveltyTracker()

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="185.220.101.34",
            auth_method="password",
        )
        enr = EnrichmentResult(ip="185.220.101.34", asn="AS208323", org="Tor Exit", country="DE", city="Frankfurt", enriched=True)

        is_novel, novelty_reasons = tracker.evaluate(ev, enr, b)
        scored = engine.evaluate(ev, enr, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.score > 0
        assert any("First-seen" in r for r in scored.reasons)


def test_new_ssh_key_critical():
    """A new SSH key addition should be CRITICAL severity."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        engine = InvariantEngine()
        tracker = NoveltyTracker()

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="ssh_key_added",
            username="deploy",
            raw_line="sshd[11442]: key added: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 for user deploy added to authorized_keys",
        )
        is_novel, novelty_reasons = tracker.evaluate(ev, None, b)
        scored = engine.evaluate(ev, None, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.severity == "CRITICAL"
        assert "UNAUTHORIZED_KEY_ADD" in scored.invariants


def test_first_sudo():
    """First sudo usage by a user should be flagged as novel."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        engine = InvariantEngine()
        tracker = NoveltyTracker()

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="sudo_used",
            username="alice",
        )
        is_novel, novelty_reasons = tracker.evaluate(ev, None, b)
        scored = engine.evaluate(ev, None, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.score > 0
        assert any("sudo" in r.lower() or "privilege" in r.lower() for r in scored.reasons)


def test_brute_force_burst_detection():
    """Multiple login failures from the same IP should trigger FAILED_AUTH_BURST."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        now = datetime(2024, 1, 15, 12, 0, 0)
        engine = InvariantEngine()
        tracker = NoveltyTracker()

        # Record 3 login failures from same IP
        for i in range(3):
            t = (now - timedelta(minutes=3 - i)).isoformat()
            ev_fail = AuthEvent(
                timestamp=t,
                event_type="login_failure",
                username="alice",
                source_ip="45.33.32.156",
            )
            b.record_event(ev_fail, None, 0, [])

        # The 4th failure should detect the burst
        ev = AuthEvent(
            timestamp=now.isoformat(),
            event_type="login_failure",
            username="alice",
            source_ip="45.33.32.156",
        )
        is_novel, novelty_reasons = tracker.evaluate(ev, None, b)
        scored = engine.evaluate(ev, None, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.score >= 25
        assert "FAILED_AUTH_BURST" in scored.invariants


def test_score_max_capped_at_100():
    """Scores should never exceed 100."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        engine = InvariantEngine(config={"correlation": {"sequence_window_min": 15}})
        tracker = NoveltyTracker()

        now = datetime(2024, 1, 15, 3, 0, 0)
        # Set up prior suspicious activity
        for i in range(5):
            t = (now - timedelta(minutes=4 - i)).isoformat()
            ev_fail = AuthEvent(
                timestamp=t,
                event_type="login_failure",
                username="alice",
                source_ip="185.220.101.34",
            )
            b.record_event(ev_fail, None, 0, [],
                          signals=["novel_remote_origin"], severity="WARNING",
                          invariants=["NOVEL_REMOTE_ORIGIN"])

        ev = AuthEvent(
            timestamp=now.isoformat(),
            event_type="login_success",
            username="alice",
            source_ip="185.220.101.34",
        )
        enr = EnrichmentResult(ip="185.220.101.34", asn="AS9999", org="Test", enriched=True)

        is_novel, novelty_reasons = tracker.evaluate(ev, enr, b)
        scored = engine.evaluate(ev, enr, b, is_novel=is_novel, novelty_reasons=novelty_reasons)
        assert scored.score <= 100
