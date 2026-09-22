"""
AuthCanary — Unit tests for PersistenceMonitor.
"""

from pathlib import Path
import plistlib
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.persistence_monitor import PersistenceMonitor
from engine.baseline import Baseline
from engine.novelty import NoveltyTracker


def test_persistence_monitor_detects_new_launch_agent(tmp_path):
    # Setup mock LaunchAgents directory
    launch_agents_dir = tmp_path / "LaunchAgents"
    launch_agents_dir.mkdir()

    shell_file = tmp_path / ".zshrc"
    shell_file.write_text("# normal zshrc\n")

    db_file = tmp_path / "baseline.db"
    baseline = Baseline(str(db_file))

    monitor = PersistenceMonitor(
        baseline=baseline,
        watched_dirs=(launch_agents_dir,),
        watched_files=(shell_file,),
    )

    # Initial scan seeds snapshot
    init_events = monitor.scan()
    assert init_events == []
    assert monitor._initialized is True

    # Drop a new suspicious plist into LaunchAgents
    bad_plist = launch_agents_dir / "com.evil.updater.plist"
    plist_data = {
        "Label": "com.evil.updater",
        "ProgramArguments": ["/tmp/updater", "--daemon"],
        "RunAtLoad": True,
    }
    bad_plist.write_bytes(plistlib.dumps(plist_data))

    # Second scan should detect the addition
    events = monitor.scan()
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "PERSISTENCE_ADDITION"
    assert "com.evil.updater" in ev.command
    assert str(bad_plist) in ev.persistence_target

    # Modify the existing plist
    plist_data["ProgramArguments"] = ["/tmp/updater", "--modified"]
    bad_plist.write_bytes(plistlib.dumps(plist_data))

    events_mod = monitor.scan()
    assert len(events_mod) == 1
    assert events_mod[0].event_type == "PERSISTENCE_MODIFIED"


def test_persistence_monitor_novelty_integration(tmp_path):
    db_file = tmp_path / "baseline.db"
    baseline = Baseline(str(db_file))
    tracker = NoveltyTracker()

    launch_agents_dir = tmp_path / "LaunchAgents"
    launch_agents_dir.mkdir()

    monitor = PersistenceMonitor(
        baseline=baseline,
        watched_dirs=(launch_agents_dir,),
        watched_files=(),
    )
    monitor.scan()

    new_plist = launch_agents_dir / "com.test.agent.plist"
    new_plist.write_text("<plist></plist>")

    events = monitor.scan()
    assert len(events) == 1
    ev = events[0]

    is_novel, reasons = tracker.evaluate(ev, None, baseline)
    assert is_novel is True
    assert any("Persistence modification" in r for r in reasons)
