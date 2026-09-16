"""
SentinelLog — Tests for the ingestion layer.

Tests regex parsing, cursor persistence, and event schema validation.
All tests use embedded sample log lines — no actual /var/log/auth.log required.
"""

import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingest.schema import AuthEvent
from ingest.cursor import CursorManager, CursorState
from ingest.adapters import LinuxAuthLogAdapter


# ── AuthEvent tests ────────────────────────────────────────────────

def test_auth_event_creation():
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="login_success",
        username="alice",
        source_ip="192.168.1.100",
        auth_method="password",
        raw_line="test line",
    )
    assert ev.username == "alice"
    assert ev.event_type == "login_success"
    assert ev.source_ip == "192.168.1.100"


def test_auth_event_to_dict():
    ev = AuthEvent(
        timestamp="2024-01-15T14:30:00",
        event_type="login_failure",
        username="bob",
    )
    d = ev.to_dict()
    assert d["username"] == "bob"
    assert d["event_type"] == "login_failure"
    assert d["source_ip"] is None
    assert d["auth_method"] is None


# ── Cursor tests ───────────────────────────────────────────────────

def test_cursor_save_load_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "cursor.json"
        mgr = CursorManager(path)

        state = CursorState(source="test", offset=1234, last_timestamp="2024-01-15T14:30:00")
        mgr.save(state)
        loaded = mgr.load()

        assert loaded.source == "test"
        assert loaded.offset == 1234
        assert loaded.last_timestamp == "2024-01-15T14:30:00"


def test_cursor_load_missing_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "nonexistent.json"
        mgr = CursorManager(path)
        state = mgr.load()
        assert state.offset == 0
        assert state.source == ""


def test_cursor_reset():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "cursor.json"
        mgr = CursorManager(path)
        mgr.save(CursorState(source="test", offset=100))
        mgr.reset()
        assert not path.exists()


# ── Adapter regex tests ────────────────────────────────────────────

def test_parse_sshd_accepted():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 14:23:05 prod-web-01 sshd[12345]: Accepted password for alice from 192.168.1.100 port 52413 ssh2"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "login_success"
    assert ev.username == "alice"
    assert ev.source_ip == "192.168.1.100"
    assert ev.auth_method == "password"


def test_parse_sshd_failed():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 02:15:33 prod-web-01 sshd[54321]: Failed publickey for bob from 10.0.0.43 port 61234 ssh2"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "login_failure"
    assert ev.username == "bob"
    assert ev.auth_method == "publickey"


def test_parse_sshd_invalid_user():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 03:00:00 prod-web-01 sshd[11111]: Failed password for invalid user admin from 45.33.32.156 port 40000 ssh2"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "login_failure"
    assert ev.username == "admin"


def test_parse_sudo():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 14:45:08 prod-web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "sudo_used"
    assert ev.username == "alice"
    assert ev.auth_method == "sudo"


def test_parse_useradd():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 09:00:00 prod-web-01 useradd[9999]: new user: name=newuser, UID=1001, GID=1001"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "new_user_created"
    assert ev.username == "newuser"


def test_parse_ssh_key_added():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 16 11:05:33 prod-web-01 sshd[11442]: key added: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 for user deploy added to authorized_keys"
    ev = adapter._parse_line(line, 2024)
    assert ev is not None
    assert ev.event_type == "ssh_key_added"
    assert ev.username == "deploy"


def test_parse_unrecognized_line():
    adapter = LinuxAuthLogAdapter.__new__(LinuxAuthLogAdapter)
    line = "Sep 10 14:00:00 prod-web-01 kernel: [12345.678] some kernel message"
    ev = adapter._parse_line(line, 2024)
    assert ev is None


def test_file_adapter_incremental_read():
    """Verify that the adapter reads incrementally from the cursor offset."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "auth.log"
        lines = [
            "Sep 10 09:00:00 host sshd[1]: Accepted password for alice from 8.8.8.8 port 50000 ssh2",
            "Sep 10 10:00:00 host sshd[2]: Accepted password for bob from 1.1.1.1 port 50001 ssh2",
            "Sep 10 11:00:00 host sshd[3]: Accepted password for alice from 8.8.8.8 port 50002 ssh2",
        ]
        log_path.write_text("\n".join(lines) + "\n")

        adapter = LinuxAuthLogAdapter(str(log_path))

        # First read: get all 3
        cursor = CursorState()
        events, new_cursor = adapter.read_events(cursor)
        assert len(events) == 3
        assert new_cursor.offset > 0

        # Second read with saved cursor: get 0 (no new lines)
        events2, cursor2 = adapter.read_events(new_cursor)
        assert len(events2) == 0

        # Append a new line
        with open(log_path, "a") as f:
            f.write("Sep 10 12:00:00 host sshd[4]: Failed password for root from 5.5.5.5 port 50003 ssh2\n")

        # Third read: get just the new line
        events3, _ = adapter.read_events(new_cursor)
        assert len(events3) == 1
        assert events3[0].username == "root"
