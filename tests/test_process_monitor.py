"""
AuthCanary — Unit tests for ProcessMonitor.
"""

from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.process_monitor import ProcessMonitor
from engine.baseline import Baseline
from engine.novelty import NoveltyTracker


def test_process_monitor_initialization():
    monitor = ProcessMonitor()
    assert monitor._initialized is False

    # First poll should initialize snapshot and return empty list
    events = monitor.poll()
    assert isinstance(events, list)
    assert monitor._initialized is True
    assert len(monitor._seen_pids) > 0


def test_process_monitor_to_auth_event():
    monitor = ProcessMonitor()
    sample = {
        "pid": 12345,
        "ppid": 100,
        "user": "alice",
        "comm": "/usr/local/bin/curl",
        "args": "curl https://example.com",
    }
    ev = monitor._to_auth_event(sample, "2026-09-22T12:00:00")
    assert ev.event_type == "PROCESS_EXEC"
    assert ev.pid == 12345
    assert ev.ppid == 100
    assert ev.username == "alice"
    assert ev.binary_path == "/usr/local/bin/curl"
    assert "curl" in ev.command


def test_process_monitor_extract_binary_path():
    assert ProcessMonitor._extract_binary_path("/bin/zsh", "zsh -l") == "/bin/zsh"
    assert ProcessMonitor._extract_binary_path("node", "/usr/local/bin/node app.js") == "/usr/local/bin/node"


def test_process_monitor_novelty_integration():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        baseline = Baseline(tmp.name)
        tracker = NoveltyTracker()

        monitor = ProcessMonitor(baseline=baseline)
        ev = monitor._to_auth_event({
            "pid": 9999,
            "ppid": 1,
            "user": "mika",
            "comm": "/opt/custom/tool",
            "args": "/opt/custom/tool --start",
        }, "2026-09-22T12:00:00")

        is_novel, reasons = tracker.evaluate(ev, None, baseline)
        assert is_novel is True
        assert any("/opt/custom/tool" in r for r in reasons)

        # Record binary into baseline
        baseline.record_binary("mika", "/opt/custom/tool")
        assert baseline.is_binary_known("mika", "/opt/custom/tool") is True

        is_novel2, _ = tracker.evaluate(ev, None, baseline)
        assert is_novel2 is False
