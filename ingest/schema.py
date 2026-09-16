"""
SentinelLog — Common event schema.

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
]

AuthMethod = Literal["password", "publickey", "sudo"]


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """A single normalized authentication event."""

    timestamp: str  # ISO 8601
    event_type: EventType
    username: str
    source_ip: str | None = None
    auth_method: AuthMethod | None = None
    raw_line: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
