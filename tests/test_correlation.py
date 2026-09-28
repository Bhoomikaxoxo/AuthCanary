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
from engine.invariants import InvariantEngine
from engine.novelty import NoveltyTracker


def _make_event(event_type: str, user: str, ip: str | None, ts: str, method: str = "password") -> AuthEvent:
    return AuthEvent(
        event_type=event_type,
        timestamp=ts,
        username=user,
        source_ip=ip,
        auth_method=method,
        raw_line=f"test line {event_type} {user}",
    )


def _score_event(engine, tracker, event, enrichment, baseline):
    """Helper: run novelty + invariant evaluation on an event."""
    is_novel, novelty_reasons = tracker.evaluate(event, enrichment, baseline)
    return engine.evaluate(
        event=event,
        enrichment=enrichment,
        baseline=baseline,
        is_novel=is_novel,
        novelty_reasons=novelty_reasons,
    )


def test_isolated_event_no_sequence_multiplier(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "correlation": {"sequence_window_min": 15},
    }
    engine = InvariantEngine(config)
    tracker = NoveltyTracker()

    now = datetime(2026, 9, 19, 10, 0, 0)
    ev1 = _make_event("login_success", "alice", "198.51.100.1", now.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)

    scored1 = _score_event(engine, tracker, ev1, enrich, baseline)
    # Single event should not have kill chain
    assert "kill_chain" not in (scored1.signals or [])


def test_correlated_escalation_sequence(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "correlation": {"sequence_window_min": 15},
    }
    engine = InvariantEngine(config)
    tracker = NoveltyTracker()

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    t1 = t0 + timedelta(minutes=5)

    # Step 1: Login from novel ASN
    ev1 = _make_event("login_success", "alice", "198.51.100.1", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)
    scored1 = _score_event(engine, tracker, ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons,
                         signals=scored1.signals, severity=scored1.severity,
                         invariants=scored1.invariants)

    # Step 2: 5 minutes later, sudo used for the first time
    ev2 = _make_event("sudo_used", "alice", None, t1.isoformat())
    scored2 = _score_event(engine, tracker, ev2, None, baseline)

    # Should detect correlated escalation (novel login → first sudo within window)
    assert scored2.severity in ("WARNING", "CRITICAL")
    assert scored2.score > 0


def test_full_kill_chain_sequence(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "correlation": {"sequence_window_min": 15},
    }
    engine = InvariantEngine(config)
    tracker = NoveltyTracker()

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    t1 = t0 + timedelta(minutes=3)
    t2 = t0 + timedelta(minutes=7)

    # Step 1: Initial access from novel ASN
    ev1 = _make_event("login_success", "bob", "198.51.100.2", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.2", asn="AS9999", org="EvilCorp", enriched=True)
    scored1 = _score_event(engine, tracker, ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons,
                         signals=scored1.signals, severity=scored1.severity,
                         invariants=scored1.invariants)

    # Step 2: Privilege escalation
    ev2 = _make_event("sudo_used", "bob", None, t1.isoformat())
    scored2 = _score_event(engine, tracker, ev2, None, baseline)
    baseline.record_event(ev2, None, scored2.score, scored2.reasons,
                         signals=scored2.signals, severity=scored2.severity,
                         invariants=scored2.invariants)

    # Step 3: Persistence planted (SSH key added)
    ev3 = _make_event("ssh_key_added", "bob", None, t2.isoformat(), method="publickey")
    scored3 = _score_event(engine, tracker, ev3, None, baseline)

    # Full kill chain: should be CRITICAL
    assert scored3.severity == "CRITICAL"
    assert scored3.score <= 100


def test_sequence_window_expiry(tmp_path):
    db_path = str(tmp_path / "baseline.db")
    baseline = Baseline(db_path=db_path, warmup_days=0, warmup_min_events=0)
    config = {
        "correlation": {"sequence_window_min": 15},
    }
    engine = InvariantEngine(config)
    tracker = NoveltyTracker()

    t0 = datetime(2026, 9, 19, 10, 0, 0)
    # Event 2 occurs 60 minutes later (well past the 15m window)
    t1 = t0 + timedelta(minutes=60)

    ev1 = _make_event("login_success", "alice", "198.51.100.1", t0.isoformat())
    enrich = EnrichmentResult(ip="198.51.100.1", asn="AS9999", org="AttackerISP", enriched=True)
    scored1 = _score_event(engine, tracker, ev1, enrich, baseline)
    baseline.record_event(ev1, enrich, scored1.score, scored1.reasons,
                         signals=scored1.signals, severity=scored1.severity,
                         invariants=scored1.invariants)

    ev2 = _make_event("sudo_used", "alice", None, t1.isoformat())
    scored2 = _score_event(engine, tracker, ev2, None, baseline)

    # Window expired → should NOT have kill chain escalation
    assert "KILL_CHAIN_ESCALATION" not in (scored2.invariants or [])
