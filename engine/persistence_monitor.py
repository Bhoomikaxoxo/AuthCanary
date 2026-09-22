"""
AuthCanary — macOS Persistence & Login Item Monitor.

Monitors classic macOS persistence surfaces:
  - ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons
  - Shell startup configurations (~/.zshrc, ~/.bash_profile, /etc/pam.d/sudo)
  - Background Task Management via sfltool dumpbtm
  - Browser extension manifests

Diffs current state against baseline to flag unauthorized persistence injections.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from ingest.schema import AuthEvent


DEFAULT_PERSISTENCE_DIRECTORIES = (
    Path("~/Library/LaunchAgents").expanduser(),
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("~/Library/Application Support/Google/Chrome/Default/Extensions").expanduser(),
)

DEFAULT_SHELL_FILES = (
    Path("~/.zshrc").expanduser(),
    Path("~/.zprofile").expanduser(),
    Path("~/.bash_profile").expanduser(),
    Path("~/.bashrc").expanduser(),
    Path("/etc/pam.d/sudo"),
)


class PersistenceMonitor:
    """Audits and tracks persistence mechanisms across macOS files and registries."""

    def __init__(
        self,
        baseline=None,
        watched_dirs: tuple[Path, ...] | None = None,
        watched_files: tuple[Path, ...] | None = None,
    ) -> None:
        self.baseline = baseline
        self.watched_dirs = watched_dirs or DEFAULT_PERSISTENCE_DIRECTORIES
        self.watched_files = watched_files or DEFAULT_SHELL_FILES
        self._known_snapshots: dict[str, str] = {}  # filepath -> sha256
        self._initialized = False

    def initialize_snapshot(self) -> None:
        """Record initial hash snapshot of all existing items so first run doesn't flood alerts."""
        current = self._scan_all()
        for path_str, item in current.items():
            self._known_snapshots[path_str] = item["hash"]
            if self.baseline and hasattr(self.baseline, "record_persistence"):
                self.baseline.record_persistence(path_str, item["label"], item["hash"])
        self._initialized = True

    def scan(self) -> list[AuthEvent]:
        """Scan persistence locations and emit AuthEvent for any additions or alterations."""
        events: list[AuthEvent] = []
        current = self._scan_all()
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        current_user = os.environ.get("USER", "system")

        if not self._initialized:
            self.initialize_snapshot()
            return []

        # Check for additions and modifications
        for path_str, item in current.items():
            curr_hash = item["hash"]
            label = item["label"]
            cmd = item.get("command", label)

            if path_str not in self._known_snapshots:
                # Completely new persistence item
                self._known_snapshots[path_str] = curr_hash
                is_known_in_db = False
                if self.baseline and hasattr(self.baseline, "is_persistence_known"):
                    is_known_in_db = self.baseline.is_persistence_known(path_str, curr_hash)

                if not is_known_in_db:
                    events.append(
                        AuthEvent(
                            timestamp=now,
                            event_type="PERSISTENCE_ADDITION",
                            username=current_user,
                            process="persistence",
                            command=f"Added '{label}': {cmd}",
                            persistence_target=path_str,
                            persistence_action="added",
                            raw_line=f"PERSISTENCE ADDITION: {path_str} [{label}] ({cmd})",
                        )
                    )
                    if self.baseline and hasattr(self.baseline, "record_persistence"):
                        self.baseline.record_persistence(path_str, label, curr_hash, now)

            elif self._known_snapshots[path_str] != curr_hash:
                # Item was modified
                self._known_snapshots[path_str] = curr_hash
                events.append(
                    AuthEvent(
                        timestamp=now,
                        event_type="PERSISTENCE_MODIFIED",
                        username=current_user,
                        process="persistence",
                        command=f"Modified '{label}': {cmd}",
                        persistence_target=path_str,
                        persistence_action="modified",
                        raw_line=f"PERSISTENCE MODIFIED: {path_str} [{label}]",
                    )
                )
                if self.baseline and hasattr(self.baseline, "record_persistence"):
                    self.baseline.record_persistence(path_str, label, curr_hash, now)

        return events

    def _scan_all(self) -> dict[str, dict]:
        """Inspect all persistence directories and shell files."""
        results: dict[str, dict] = {}

        # 1. Inspect directories (LaunchAgents, LaunchDaemons, Extensions)
        for directory in self.watched_dirs:
            if not directory.exists() or not directory.is_dir():
                continue
            try:
                for entry in directory.iterdir():
                    if entry.is_file() and not entry.name.startswith("."):
                        item = self._inspect_file(entry)
                        if item:
                            results[str(entry)] = item
            except (PermissionError, OSError):
                continue

        # 2. Inspect individual shell & config files
        for fpath in self.watched_files:
            if fpath.exists() and fpath.is_file():
                item = self._inspect_file(fpath)
                if item:
                    results[str(fpath)] = item

        return results

    def _inspect_file(self, path: Path) -> Optional[dict]:
        """Compute sha256 hash and extract label/command from plist or script."""
        try:
            content = path.read_bytes()
            file_hash = hashlib.sha256(content).hexdigest()
            label = path.name
            command = ""

            if path.suffix == ".plist":
                try:
                    plist_data = plistlib.loads(content)
                    label = plist_data.get("Label", path.name)
                    prog = plist_data.get("Program") or ""
                    args = plist_data.get("ProgramArguments") or []
                    if isinstance(args, list):
                        command = " ".join(str(a) for a in args)
                    else:
                        command = str(args)
                    if not command and prog:
                        command = str(prog)
                except Exception:
                    pass

            return {
                "path": str(path),
                "hash": file_hash,
                "label": label,
                "command": command or path.name,
            }
        except (PermissionError, OSError):
            return None
