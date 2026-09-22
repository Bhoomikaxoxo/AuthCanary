"""
AuthCanary — Common event schema.

Every adapter normalizes raw log lines into this single dataclass.
All downstream modules (enrichment, scoring, output) consume only this type.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Literal


EventType = Literal[
    "login_success",
    "login_failure",
    "sudo_used",
    "ssh_key_added",
    "new_user_created",
    "system_auth",
    "privilege_elevation",
    "tcc_access",
]

AuthMethod = Literal["password", "publickey", "sudo", "touch_id", "system", "unknown"]


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """A single normalized authentication event."""

    timestamp: str  # ISO 8601
    event_type: EventType | str
    username: str
    source_ip: str | None = None
    auth_method: AuthMethod | str | None = None
    raw_line: str = ""
    process: str = "system"
    pid: int = 0
    subsystem: str = ""
    category: str = ""
    command: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
