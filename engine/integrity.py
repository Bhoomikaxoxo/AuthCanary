"""
AuthCanary — File Integrity Monitoring (FIM) & Configuration Drift Detection.

Monitors critical security configurations (e.g. sshd_config, authorized_keys, sudoers)
to detect persistence mechanisms or unauthorized edits that bypass authentication logs.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Sequence

from engine.playbooks import get_playbook


DEFAULT_TARGETS = [
    "/etc/ssh/sshd_config",
    "~/.ssh/authorized_keys",
    "/etc/sudoers",
    "/etc/sudoers.d",
]


@dataclass(slots=True)
class IntegrityResult:
    """Outcome of an integrity check on a monitored file."""

    filepath: str
    status: str            # "OK", "MODIFIED", "CREATED", "DELETED", "PERMISSION_DENIED", "ERROR"
    sha256: str = ""
    previous_sha256: str = ""
    message: str = ""
    is_alert: bool = False
    playbook: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class IntegrityChecker:
    """Lightweight File Integrity Monitor backed by AuthCanary SQLite database."""

    def __init__(self, db_path: str, targets: Sequence[str] | None = None) -> None:
        self.db_path = str(Path(db_path).expanduser())
        self.targets = list(targets if targets is not None else DEFAULT_TARGETS)
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_integrity_hashes (
                    filepath     TEXT PRIMARY KEY,
                    sha256       TEXT,
                    mtime        REAL,
                    size         INTEGER,
                    last_checked TEXT,
                    status       TEXT
                )
                """
            )

    def _resolve_paths(self) -> set[Path]:
        """Resolve target strings to actual files, expanding directories and home dirs."""
        resolved: set[Path] = set()
        for target_str in self.targets:
            p = Path(target_str).expanduser()
            if not p.exists():
                # Keep parent or target so we can record non-existence if previously tracked
                resolved.add(p)
                continue

            if p.is_dir():
                try:
                    for child in p.iterdir():
                        if child.is_file():
                            resolved.add(child)
                except PermissionError:
                    resolved.add(p)
            else:
                resolved.add(p)
        return resolved

    def _hash_file(self, path: Path) -> tuple[str, float, int]:
        """Compute sha256 hash, mtime, and size for a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        stat = path.stat()
        return h.hexdigest(), stat.st_mtime, stat.st_size

    def check(self, dry_run: bool = False) -> list[IntegrityResult]:
        """Run integrity audit across all monitored targets against SQLite baseline."""
        results: list[IntegrityResult] = []
        resolved_files = self._resolve_paths()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # Load current baseline state
            rows = conn.execute(
                "SELECT filepath, sha256, mtime, size, status FROM file_integrity_hashes"
            ).fetchall()
            db_state = {r["filepath"]: dict(r) for r in rows}

        now_str = datetime.now().isoformat()
        current_paths_str = set()

        for path in resolved_files:
            path_str = str(path)
            current_paths_str.add(path_str)

            if not path.exists():
                if path_str in db_state and db_state[path_str]["status"] != "DELETED":
                    prev = db_state[path_str]["sha256"]
                    res = IntegrityResult(
                        filepath=path_str,
                        status="DELETED",
                        previous_sha256=prev,
                        message=f"Critical configuration file was deleted: {path_str}",
                        is_alert=True,
                        playbook=get_playbook(signals=["integrity_drift"], path=path_str),
                    )
                    results.append(res)
                    if not dry_run:
                        self._update_db(path_str, "", 0.0, 0, now_str, "DELETED")
                continue

            # File exists — attempt to read and hash
            try:
                sha256, mtime, size = self._hash_file(path)
            except PermissionError:
                res = IntegrityResult(
                    filepath=path_str,
                    status="PERMISSION_DENIED",
                    message=(
                        f"Permission denied reading {path_str}. "
                        f"Run AuthCanary with elevated permissions to monitor."
                    ),
                    is_alert=False,
                )
                results.append(res)
                if not dry_run:
                    self._update_db(path_str, "", 0.0, 0, now_str, "PERMISSION_DENIED")
                continue
            except Exception as e:
                res = IntegrityResult(
                    filepath=path_str,
                    status="ERROR",
                    message=f"Error checking {path_str}: {e}",
                    is_alert=False,
                )
                results.append(res)
                continue

            # Compare with DB baseline
            if path_str not in db_state:
                # First time seeing this file
                # If the DB already has other files, this is a newly created file!
                is_new = len(db_state) > 0
                status = "CREATED" if is_new else "OK"
                is_alert = is_new
                msg = (
                    f"New security file created: {path_str}"
                    if is_new
                    else f"Established initial integrity baseline for {path_str}"
                )
                res = IntegrityResult(
                    filepath=path_str,
                    status=status,
                    sha256=sha256,
                    message=msg,
                    is_alert=is_alert,
                    playbook=get_playbook(signals=["integrity_drift"], path=path_str) if is_alert else "",
                )
                results.append(res)
                if not dry_run:
                    self._update_db(path_str, sha256, mtime, size, now_str, status)
            else:
                prev_record = db_state[path_str]
                prev_sha256 = prev_record["sha256"]

                if prev_record["status"] in ("PERMISSION_DENIED", "DELETED") or prev_sha256 != sha256:
                    if prev_sha256 and prev_sha256 != sha256:
                        status = "MODIFIED"
                        is_alert = True
                        msg = (
                            f"Configuration drift detected in {path_str}! "
                            f"SHA256 changed: {prev_sha256[:10]}... → {sha256[:10]}..."
                        )
                    else:
                        status = "OK"
                        is_alert = False
                        msg = f"Integrity check passed for {path_str}"

                    res = IntegrityResult(
                        filepath=path_str,
                        status=status,
                        sha256=sha256,
                        previous_sha256=prev_sha256,
                        message=msg,
                        is_alert=is_alert,
                        playbook=get_playbook(signals=["integrity_drift"], path=path_str) if is_alert else "",
                    )
                    results.append(res)
                    if not dry_run:
                        self._update_db(path_str, sha256, mtime, size, now_str, status)
                else:
                    # Clean match
                    results.append(
                        IntegrityResult(
                            filepath=path_str,
                            status="OK",
                            sha256=sha256,
                            previous_sha256=prev_sha256,
                            message=f"Integrity check passed for {path_str}",
                            is_alert=False,
                        )
                    )
                    if not dry_run:
                        self._update_db(path_str, sha256, mtime, size, now_str, "OK")

        return results

    def _update_db(self, filepath: str, sha256: str, mtime: float,
                   size: int, checked_at: str, status: str) -> None:
        """Upsert file hash record into SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO file_integrity_hashes
                (filepath, sha256, mtime, size, last_checked, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(filepath) DO UPDATE SET
                    sha256 = excluded.sha256,
                    mtime = excluded.mtime,
                    size = excluded.size,
                    last_checked = excluded.last_checked,
                    status = excluded.status
                """,
                (filepath, sha256, mtime, size, checked_at, status),
            )
