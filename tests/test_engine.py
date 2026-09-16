"""
SentinelLog — Tests for the engine layer.

Tests baseline persistence, warm-up tracking, statistics calculation,
and the anomaly scoring engine (weights, signals, thresholds, and limits).
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
from engine.scoring import Scorer, DEFAULT_WEIGHTS


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


# ── Scorer tests ───────────────────────────────────────────────────

def test_scorer_clean_known_event():
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

        config = {
            "scoring": {
                "alert_threshold": 40,
                "weights": DEFAULT_WEIGHTS,
            }
        }
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="8.8.8.8",
            auth_method="password",
        )
        enr = EnrichmentResult(ip="8.8.8.8", asn="AS15169", org="Google", enriched=True)

        scored = scorer.score(ev, enr, b)
        assert scored.score == 0
        assert len(scored.reasons) == 0
        assert not scorer.is_alert(scored)


def test_scorer_new_ip_new_asn():
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

        config = {"scoring": {"alert_threshold": 40}}
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="login_success",
            username="alice",
            source_ip="185.220.101.34",
            auth_method="password",
        )
        enr = EnrichmentResult(ip="185.220.101.34", asn="AS208323", org="Tor Exit", country="DE", city="Frankfurt", enriched=True)

        scored = scorer.score(ev, enr, b)
        assert scored.score >= 35
        assert any("New IP" in r and "unknown ASN" in r for r in scored.reasons)


def test_scorer_new_ssh_key_always_alert():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        config = {
            "scoring": {
                "alert_threshold": 60,
                "always_alert": ["new_ssh_key"],
            }
        }
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="ssh_key_added",
            username="deploy",
            raw_line="sshd[11442]: key added: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 for user deploy added to authorized_keys",
        )
        scored = scorer.score(ev, None, b)
        assert scored.score >= 40
        assert any("SSH key" in r for r in scored.reasons)
        assert scorer.is_alert(scored)


def test_scorer_first_sudo():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        config = {"scoring": {"alert_threshold": 40}}
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp="2024-01-15T14:30:00",
            event_type="sudo_used",
            username="alice",
        )
        scored = scorer.score(ev, None, b)
        assert scored.score >= 30
        assert any("First sudo usage by 'alice'" in r for r in scored.reasons)


def test_scorer_brute_force_success():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        now = datetime(2024, 1, 15, 12, 0, 0)
        # Record 4 login failures from same IP
        for i in range(4):
            t = (now - timedelta(minutes=4 - i)).isoformat()
            ev_fail = AuthEvent(
                timestamp=t,
                event_type="login_failure",
                username="alice",
                source_ip="45.33.32.156",
            )
            b.record_event(ev_fail, None, 0, [])

        config = {
            "scoring": {
                "brute_force_window_min": 10,
                "brute_force_min_failures": 3,
            }
        }
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp=now.isoformat(),
            event_type="login_success",
            username="alice",
            source_ip="45.33.32.156",
        )
        scored = scorer.score(ev, None, b)
        assert scored.score >= 35
        assert any("brute-force" in r for r in scored.reasons)


def test_scorer_max_capped_at_100():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        b = Baseline(tmp.name)
        now = datetime(2024, 1, 15, 3, 0, 0)
        for i in range(5):
            t = (now - timedelta(minutes=4 - i)).isoformat()
            ev_fail = AuthEvent(
                timestamp=t,
                event_type="login_failure",
                username="alice",
                source_ip="185.220.101.34",
            )
            b.record_event(ev_fail, None, 0, [])

        config = {
            "scoring": {
                "weights": {
                    "new_asn": 60,
                    "brute_force_pattern": 60,
                }
            }
        }
        scorer = Scorer(config)

        ev = AuthEvent(
            timestamp=now.isoformat(),
            event_type="login_success",
            username="alice",
            source_ip="185.220.101.34",
        )
        enr = EnrichmentResult(ip="185.220.101.34", asn="AS9999", org="Test", enriched=True)

        scored = scorer.score(ev, enr, b)
        assert scored.score == 100
