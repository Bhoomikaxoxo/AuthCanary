"""
AuthCanary — Ingestion cursor persistence.

Tracks file offsets / journal cursors so re-running doesn't reprocess
the entire log. Persists to a JSON file at the path specified in config.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class CursorState:
    """Serializable read-position bookmark."""

    source: str = ""          # Adapter name or file path
    offset: int = 0           # Byte offset into the log file
    last_timestamp: str = ""  # ISO 8601 timestamp of last processed event
    journal_cursor: str = ""  # For journald: opaque cursor string


class CursorManager:
    """Save / load cursor state to a JSON file."""

    def __init__(self, cursor_path: str | Path) -> None:
        self.path = Path(cursor_path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> CursorState:
        """Load cursor from disk, or return a fresh one if none exists."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return CursorState(**data)
            except (json.JSONDecodeError, TypeError, KeyError):
                return CursorState()
        return CursorState()

    def save(self, state: CursorState) -> None:
        """Persist cursor to disk."""
        self.path.write_text(
            json.dumps(asdict(state), indent=2),
            encoding="utf-8",
        )

    def reset(self) -> None:
        """Delete persisted cursor — forces a full reprocess on next run."""
        if self.path.exists():
            self.path.unlink()
