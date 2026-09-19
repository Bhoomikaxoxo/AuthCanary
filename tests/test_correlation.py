"""
AuthCanary — Tests for correlated sequence scoring & attack chain detection.
"""

from datetime import datetime, timedelta
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult
from engine.baseline import Baseline
from engine.scoring import Scorer


def _make_event(event_type: str, user: str, ip: str | None, ts: str, method: str = "password") -> AuthEvent:
    return AuthEvent(
        event_type=event_type,
        timestamp=ts,
        username=user,
        source_ip=ip,
        auth_method=method,
        raw_line=f"test line {event_type} {user}",
    )


def test_isolated_event_no_sequence_multiplier(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "scoring": {"weights": {"new_ip_new_asn": 35, "first_sudo": 30}},
        "correlation": {"sequence_window_min": 15, "sequence_multiplier": 1.5},
    }
    scorer = Scorer(config)

    now = datetime(2026, 9, 19, 10, 0, 0)
    ev1 = _make_event("login_success", "alice", "198.51.100.1", now.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)

    scored1 = scorer.score(ev1, enrich, baseline)
    # Single event should not have sequence multiplier
    assert scored1.score == 35
    assert "kill_chain" not in scored1.signals
    assert "correlated_escalation" not in scored1.signals


def test_correlated_escalation_sequence(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "scoring": {"weights": {"new_ip_new_asn": 35, "first_sudo": 30}},
        "correlation": {"sequence_window_min": 15, "sequence_multiplier": 1.5},
    }
    scorer = Scorer(config)

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    t1 = t0 + timedelta(minutes=5)

    # Step 1: Login from novel ASN
    ev1 = _make_event("login_success", "alice", "198.51.100.1", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)
    scored1 = scorer.score(ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons, signals=scored1.signals)

    # Step 2: 5 minutes later, sudo used for the first time
    ev2 = _make_event("sudo_used", "alice", None, t1.isoformat())
    scored2 = scorer.score(ev2, None, baseline)

    # Escalation (base 30) * 1.5 multiplier + 25 bonus = 70
    assert scored2.score == 70
    assert "correlated_escalation" in scored2.signals
    assert any("Correlated Sequence" in r for r in scored2.reasons)
    assert scorer.is_alert(scored2) is True
    assert scored2.playbook != ""


def test_full_kill_chain_sequence_order_and_capping(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "scoring": {"weights": {"new_ip_new_asn": 35, "first_sudo": 30, "new_ssh_key": 40}},
        "correlation": {"sequence_window_min": 15, "sequence_multiplier": 1.5},
    }
    scorer = Scorer(config)

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    t1 = t0 + timedelta(minutes=3)
    t2 = t0 + timedelta(minutes=7)

    # Step 1: Initial access from novel ASN
    ev1 = _make_event("login_success", "bob", "198.51.100.2", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.2", asn="AS9999", org="EvilCorp", enriched=True)
    scored1 = scorer.score(ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons, signals=scored1.signals)

    # Step 2: Privilege escalation
    ev2 = _make_event("sudo_used", "bob", None, t1.isoformat())
    scored2 = scorer.score(ev2, None, baseline)
    baseline.record_event(ev2, None, scored2.score, scored2.reasons, signals=scored2.signals)

    # Step 3: Persistence planted (SSH key added)
    ev3 = _make_event("ssh_key_added", "bob", None, t2.isoformat(), method="publickey")
    scored3 = scorer.score(ev3, None, baseline)

    # Trifecta: Base 40 * 1.8 + 40 bonus = 112 -> strictly capped at 100
    assert scored3.score == 100
    assert "kill_chain" in scored3.signals
    assert any("CRITICAL KILL CHAIN" in r for r in scored3.reasons)
    assert scorer.is_alert(scored3) is True
    assert "High-Priority Incident Response" in scored3.playbook


def test_sequence_window_expiry(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "scoring": {"weights": {"new_ip_new_asn": 35, "first_sudo": 30}},
        "correlation": {"sequence_window_min": 15, "sequence_multiplier": 1.5},
    }
    scorer = Scorer(config)

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    # Event 2 occurs 60 minutes later (well past the 15m window)
    t1 = t0 + timedelta(minutes=60)

    ev1 = _make_event("login_success", "alice", "198.51.100.1", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)
    scored1 = scorer.score(ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons, signals=scored1.signals)

    ev2 = _make_event("sudo_used", "alice", None, t1.isoformat())
    scored2 = scorer.score(ev2, None, baseline)

    # Window expired -> regular base score of 30, no multiplier or chain bonus
    assert scored2.score == 30
    assert "correlated_escalation" not in scored2.signals
