"""
SentinelLog — Log source adapters.

Each adapter normalizes a platform-specific log format into AuthEvent objects.
The get_adapter() factory auto-detects which adapter to use at runtime.

Supported:
  - LinuxAuthLogAdapter    — /var/log/auth.log (Debian/Ubuntu)
  - LinuxJournaldAdapter   — journalctl -u ssh (systemd)
  - MacOSUnifiedLogAdapter — log show --predicate 'process == "sshd"'
  - WindowsEventLogAdapter — stub (v2)
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

from ingest.cursor import CursorState
from ingest.schema import AuthEvent


# ── Abstract base ──────────────────────────────────────────────────

class OSAdapter(ABC):
    """Interface every log-source adapter must implement."""

    @staticmethod
    @abstractmethod
    def detect() -> bool:
        """Return True if this adapter's log source is available on the host."""
        ...

    @abstractmethod
    def read_events(self, cursor: CursorState) -> tuple[list[AuthEvent], CursorState]:
        """
        Read new events starting from *cursor*.
        Returns (events, updated_cursor).
        """
        ...


# ── Regex patterns for auth.log parsing ────────────────────────────

# sshd accepted/failed
_RE_SSHD = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed)\s+(?P<method>password|publickey)\s+"
    r"for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)"
)

# sudo invocation
_RE_SUDO = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sudo:\s+(?P<user>\S+)\s+:"
)

# useradd / adduser
_RE_USERADD = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+useradd\[\d+\]:\s+new user:\s+name=(?P<user>[^\s,]+)"
)

# SSH key added (authorized_keys modification via sshd or ssh-agent)
_RE_SSH_KEY = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"key added:.*(?:SHA256:|fingerprint\s+)(?P<fingerprint>\S+)"
    r".*for user (?P<user>\S+)"
)


def _parse_syslog_timestamp(month: str, day: str, time_str: str,
                            ref_year: int | None = None) -> str:
    """Convert syslog month-day-time to ISO 8601.

    auth.log doesn't include the year, so we infer it from the reference
    year (file mtime or current year).
    """
    year = ref_year or datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {month} {day} {time_str}",
                               "%Y %b %d %H:%M:%S")
    except ValueError:
        dt = datetime.now()
    return dt.isoformat()


# ── Linux /var/log/auth.log ────────────────────────────────────────

class LinuxAuthLogAdapter(OSAdapter):
    """Parses /var/log/auth.log (Debian / Ubuntu format)."""

    DEFAULT_PATH = "/var/log/auth.log"

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path or self.DEFAULT_PATH)

    @staticmethod
    def detect() -> bool:
        return Path(LinuxAuthLogAdapter.DEFAULT_PATH).exists()

    def read_events(self, cursor: CursorState) -> tuple[list[AuthEvent], CursorState]:
        if not self.path.exists():
            return [], cursor

        ref_year = datetime.fromtimestamp(self.path.stat().st_mtime).year
        events: list[AuthEvent] = []

        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(cursor.offset)
            for line in fh:
                line = line.rstrip("\n")
                ev = self._parse_line(line, ref_year)
                if ev:
                    events.append(ev)
            new_offset = fh.tell()

        new_cursor = CursorState(
            source=str(self.path),
            offset=new_offset,
            last_timestamp=events[-1].timestamp if events else cursor.last_timestamp,
        )
        return events, new_cursor

    def _parse_line(self, line: str, ref_year: int) -> AuthEvent | None:
        # SSH login (accepted or failed)
        m = _RE_SSHD.search(line)
        if m:
            ts = _parse_syslog_timestamp(
                m.group("month"), m.group("day"), m.group("time"), ref_year)
            status = m.group("status")
            return AuthEvent(
                timestamp=ts,
                event_type="login_success" if status == "Accepted" else "login_failure",
                username=m.group("user"),
                source_ip=m.group("ip"),
                auth_method=m.group("method"),  # type: ignore[arg-type]
                raw_line=line,
            )

        # sudo
        m = _RE_SUDO.search(line)
        if m:
            ts = _parse_syslog_timestamp(
                m.group("month"), m.group("day"), m.group("time"), ref_year)
            return AuthEvent(
                timestamp=ts,
                event_type="sudo_used",
                username=m.group("user"),
                auth_method="sudo",
                raw_line=line,
            )

        # new user
        m = _RE_USERADD.search(line)
        if m:
            ts = _parse_syslog_timestamp(
                m.group("month"), m.group("day"), m.group("time"), ref_year)
            return AuthEvent(
                timestamp=ts,
                event_type="new_user_created",
                username=m.group("user"),
                raw_line=line,
            )

        # SSH key added
        m = _RE_SSH_KEY.search(line)
        if m:
            ts = _parse_syslog_timestamp(
                m.group("month"), m.group("day"), m.group("time"), ref_year)
            return AuthEvent(
                timestamp=ts,
                event_type="ssh_key_added",
                username=m.group("user"),
                raw_line=line,
            )

        return None


# ── Linux journald ─────────────────────────────────────────────────

class LinuxJournaldAdapter(OSAdapter):
    """Reads SSH events from systemd journal (preferred on modern systemd distros)."""

    def __init__(self) -> None:
        pass

    @staticmethod
    def detect() -> bool:
        if platform.system() != "Linux":
            return False
        try:
            r = subprocess.run(
                ["journalctl", "--version"],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
        except FileNotFoundError:
            return False

    def read_events(self, cursor: CursorState) -> tuple[list[AuthEvent], CursorState]:
        cmd = [
            "journalctl", "-u", "ssh", "-u", "sshd",
            "--output=json", "--no-pager",
        ]
        if cursor.journal_cursor:
            cmd += ["--after-cursor", cursor.journal_cursor]
        else:
            cmd += ["--since", "7 days ago"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return [], cursor

        events: list[AuthEvent] = []
        last_cursor = cursor.journal_cursor

        for raw_line in result.stdout.strip().splitlines():
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            last_cursor = entry.get("__CURSOR", last_cursor)
            msg = entry.get("MESSAGE", "")
            ev = self._parse_message(msg, entry, raw_line)
            if ev:
                events.append(ev)

        new_cursor = CursorState(
            source="journald",
            journal_cursor=last_cursor,
            last_timestamp=events[-1].timestamp if events else cursor.last_timestamp,
        )
        return events, new_cursor

    def _parse_message(self, msg: str, entry: dict,
                       raw_line: str) -> AuthEvent | None:
        # Reuse the same regex patterns
        ts_usec = entry.get("__REALTIME_TIMESTAMP", "")
        if ts_usec:
            try:
                ts = datetime.fromtimestamp(int(ts_usec) / 1_000_000).isoformat()
            except (ValueError, OSError):
                ts = datetime.now().isoformat()
        else:
            ts = datetime.now().isoformat()

        # Accepted / Failed login
        m = re.search(
            r"(Accepted|Failed)\s+(password|publickey)\s+for\s+"
            r"(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)", msg)
        if m:
            return AuthEvent(
                timestamp=ts,
                event_type="login_success" if m.group(1) == "Accepted" else "login_failure",
                username=m.group(3),
                source_ip=m.group(4),
                auth_method=m.group(2),  # type: ignore[arg-type]
                raw_line=raw_line,
            )

        # sudo
        m = re.search(r"sudo:\s+(\S+)\s+:", msg)
        if m:
            return AuthEvent(
                timestamp=ts,
                event_type="sudo_used",
                username=m.group(1),
                auth_method="sudo",
                raw_line=raw_line,
            )

        return None


# ── macOS unified log + session history ───────────────────────────

class MacOSUnifiedLogAdapter(OSAdapter):
    """Reads auth, screensaver unlock, sudo, and SSH events from macOS."""

    def __init__(self) -> None:
        self.log_bin = "/usr/bin/log" if Path("/usr/bin/log").exists() else "log"

    @staticmethod
    def detect() -> bool:
        return platform.system() == "Darwin"

    def read_events(self, cursor: CursorState) -> tuple[list[AuthEvent], CursorState]:
        events: list[AuthEvent] = []

        # On first run (empty cursor), also ingest historical session logins from `last`
        if not cursor.last_timestamp:
            events.extend(self._read_last_logins())

        # Predicate for macOS unified logging system:
        # captures sshd, sudo, and authd (Touch ID / password / screensaver / loginwindow)
        predicate = (
            '(process == "sshd") OR '
            '(process == "sudo") OR '
            '(subsystem == "com.apple.Authorization" AND '
            '(eventMessage CONTAINS "authenticated as user" OR eventMessage CONTAINS "Failed authorizing"))'
        )

        cmd = [
            self.log_bin, "show",
            "--predicate", predicate,
            "--style", "json",
        ]

        if cursor.last_timestamp:
            cmd += ["--start", cursor.last_timestamp]
        else:
            cmd += ["--last", "48h"]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            result = None

        if result and result.stdout.strip():
            raw = result.stdout.strip()
            idx = raw.find("[")
            if idx != -1:
                raw = raw[idx:]
            try:
                entries = json.loads(raw)
            except json.JSONDecodeError:
                entries = []

            for entry in entries:
                msg = entry.get("eventMessage", "")
                ts = entry.get("timestamp", datetime.now().isoformat())
                ev = self._parse_message(msg, ts, json.dumps(entry))
                if ev:
                    events.append(ev)

        # Sort all events chronologically
        events.sort(key=lambda e: e.timestamp)

        new_cursor = CursorState(
            source="macos_unified_log",
            last_timestamp=events[-1].timestamp if events else cursor.last_timestamp,
        )
        return events, new_cursor

    def _read_last_logins(self) -> list[AuthEvent]:
        """Read historical login sessions using the macOS `last` utility."""
        events: list[AuthEvent] = []
        try:
            res = subprocess.run(["last", "-n", "60"], capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        current_year = datetime.now().year
        for line in res.stdout.strip().splitlines():
            if not line or any(k in line for k in ("reboot", "shutdown", "wtmp begins")):
                continue
            m = re.match(r"^(\S+)\s+(\S+)\s+\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2})", line)
            if m:
                user, tty, month, day, time_str = m.groups()
                try:
                    dt = datetime.strptime(f"{current_year} {month} {day} {time_str}", "%Y %b %d %H:%M")
                    # If parsed date is in future, it was from previous year
                    if dt > datetime.now():
                        dt = dt.replace(year=current_year - 1)
                    events.append(AuthEvent(
                        timestamp=dt.isoformat(),
                        event_type="login_success",
                        username=user,
                        source_ip="127.0.0.1",
                        auth_method="password",
                        raw_line=line,
                    ))
                except Exception:
                    continue
        return events

    def _parse_message(self, msg: str, ts: str,
                       raw_line: str) -> AuthEvent | None:
        # 1. SSH login accepted / failed
        m = re.search(
            r"(Accepted|Failed)\s+(password|publickey)\s+for\s+"
            r"(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)", msg)
        if m:
            return AuthEvent(
                timestamp=ts,
                event_type="login_success" if m.group(1) == "Accepted" else "login_failure",
                username=m.group(3),
                source_ip=m.group(4),
                auth_method=m.group(2),  # type: ignore[arg-type]
                raw_line=raw_line,
            )

        # 2. macOS screen unlock / authorization (authd)
        m = re.search(r"authenticated as user (\S+) \(UID \d+\) for right '([^']+)'", msg)
        if m:
            return AuthEvent(
                timestamp=ts,
                event_type="login_success",
                username=m.group(1),
                source_ip="127.0.0.1",
                auth_method="password",
                raw_line=raw_line,
            )

        # 3. macOS auth failed
        if "Failed authorizing right" in msg:
            m = re.search(r"for user\s+(\S+)", msg)
            user = m.group(1) if m else "unknown"
            return AuthEvent(
                timestamp=ts,
                event_type="login_failure",
                username=user,
                source_ip="127.0.0.1",
                auth_method="password",
                raw_line=raw_line,
            )

        # 4. sudo execution
        m = re.search(r"sudo:\s+(\S+)\s+:", msg)
        if m:
            return AuthEvent(
                timestamp=ts,
                event_type="sudo_used",
                username=m.group(1),
                source_ip="127.0.0.1",
                auth_method="sudo",
                raw_line=raw_line,
            )

        return None


# ── Windows (stub) ─────────────────────────────────────────────────

class WindowsEventLogAdapter(OSAdapter):
    """Placeholder for Windows Event Log (4624/4625/4672) — v2."""

    @staticmethod
    def detect() -> bool:
        return platform.system() == "Windows"

    def read_events(self, cursor: CursorState) -> tuple[list[AuthEvent], CursorState]:
        raise NotImplementedError(
            "Windows Event Log support is planned for v2. "
            "Contributions welcome — see README.md § Extending."
        )


# ── File-based adapter (for synthetic / arbitrary auth.log files) ──

class FileAuthLogAdapter(LinuxAuthLogAdapter):
    """Reads from any auth.log-formatted file (e.g. synthetic test data).

    Identical to LinuxAuthLogAdapter but skips the detect() OS check.
    Used when --log-source points at an explicit file path.
    """

    def __init__(self, path: str) -> None:
        super().__init__(path=path)

    @staticmethod
    def detect() -> bool:
        return True  # Always usable when explicitly requested


# ── Factory ────────────────────────────────────────────────────────

_ADAPTER_PRIORITY: list[type[OSAdapter]] = [
    LinuxAuthLogAdapter,
    LinuxJournaldAdapter,
    MacOSUnifiedLogAdapter,
    WindowsEventLogAdapter,
]


def get_adapter(log_source: str = "auto") -> OSAdapter:
    """Auto-detect or explicitly select a log adapter.

    Args:
        log_source: "auto" for detection, or an explicit file path.

    Returns:
        An instantiated adapter ready to call read_events().

    Raises:
        RuntimeError: if no suitable adapter is found.
    """
    # Explicit file path — use the file adapter
    if log_source not in ("auto", "journald"):
        path = Path(log_source)
        if path.exists():
            return FileAuthLogAdapter(str(path))
        raise RuntimeError(
            f"Log source file not found: {log_source}\n"
            f"Check the 'log_source.path' value in config.yaml."
        )

    if log_source == "journald":
        return LinuxJournaldAdapter()

    # Auto-detect
    for adapter_cls in _ADAPTER_PRIORITY:
        if adapter_cls.detect():
            if adapter_cls is WindowsEventLogAdapter:
                raise RuntimeError(
                    "Windows detected but not yet supported. "
                    "See README.md for planned v2 support."
                )
            return adapter_cls()

    raise RuntimeError(
        "Could not detect a supported log source on this system.\n"
        "Supported: /var/log/auth.log (Debian/Ubuntu), "
        "journalctl (systemd), macOS unified log.\n"
        "You can also point at a file explicitly with --log-source."
    )
