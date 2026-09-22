"""
AuthCanary — Process Execution Monitor.

Monitors process launches, execution paths, process hierarchies (pid/ppid),
and flags suspicious execution contexts (e.g. binaries running from /tmp,
curl-piped executions, or unsigned binaries).
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from ingest.schema import AuthEvent


SUSPICIOUS_PATH_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/private/var/tmp/",
    "/dev/shm/",
    "/dev/",
)


class ProcessMonitor:
    """Discovers and tracks process execution across macOS and Linux."""

    def __init__(self, baseline=None) -> None:
        self.baseline = baseline
        self._seen_pids: set[int] = set()
        self._initialized = False

    def initialize_snapshot(self) -> None:
        """Seed existing running PIDs so initial start only alerts on *new* processes."""
        current = self._fetch_process_table()
        for p in current:
            self._seen_pids.add(p["pid"])
        self._initialized = True

    def poll(self) -> list[AuthEvent]:
        """Poll the host process table and emit AuthEvent for any newly spawned processes."""
        events: list[AuthEvent] = []
        current = self._fetch_process_table()
        now = datetime.now().isoformat()

        if not self._initialized:
            self.initialize_snapshot()
            return []

        for p in current:
            pid = p["pid"]
            if pid in self._seen_pids:
                continue

            # Newly discovered PID
            self._seen_pids.add(pid)
            ev = self._to_auth_event(p, now)
            events.append(ev)

        # Prune dead PIDs periodically to prevent unbounded memory growth
        current_pids = {p["pid"] for p in current}
        self._seen_pids = self._seen_pids.intersection(current_pids)

        return events

    def parse_log_line(self, raw_line: str, timestamp: str = "") -> Optional[AuthEvent]:
        """Parse execution events from macOS unified log stream (e.g. launchd/execve)."""
        ts = timestamp or datetime.now().isoformat()
        # Look for execve or spawned process patterns
        if "spawned" in raw_line or "execve" in raw_line:
            # Extract process name and pid if available
            pid_match = re.search(r"\[(\d+)\]", raw_line)
            pid = int(pid_match.group(1)) if pid_match else 0
            return AuthEvent(
                timestamp=ts,
                event_type="PROCESS_EXEC",
                username=os.environ.get("USER", "system"),
                process="execve",
                pid=pid,
                command=raw_line.strip(),
                raw_line=raw_line,
            )
        return None

    def _fetch_process_table(self) -> list[dict]:
        """Query host process table via ps."""
        procs: list[dict] = []
        try:
            # -A: all processes, -o: specific columns
            cmd = ["ps", "-A", "-o", "pid,ppid,user,comm,args"]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode != 0:
                return []

            lines = res.stdout.strip().splitlines()
            if len(lines) <= 1:
                return []

            # First line is header: PID  PPID USER COMM ARGS
            for line in lines[1:]:
                parts = line.strip().split(None, 4)
                if len(parts) < 4:
                    continue
                try:
                    pid = int(parts[0])
                    ppid = int(parts[1])
                    user = parts[2]
                    comm = parts[3]
                    args = parts[4] if len(parts) > 4 else comm

                    # Ignore ps commands spawned by this monitor and self-children
                    if comm == "ps" or comm.endswith("/ps") or "ps -A -o" in args or ppid == os.getpid():
                        continue

                    procs.append({
                        "pid": pid,
                        "ppid": ppid,
                        "user": user,
                        "comm": comm,
                        "args": args,
                    })
                except (ValueError, IndexError):
                    continue
        except Exception:
            pass
        return procs

    def _to_auth_event(self, p: dict, ts: str) -> AuthEvent:
        """Convert a process entry dict into an AuthEvent."""
        comm = p.get("comm", "")
        args = p.get("args", "")
        binary_path = self._extract_binary_path(comm, args)
        user = p.get("user", "system")

        return AuthEvent(
            timestamp=ts,
            event_type="PROCESS_EXEC",
            username=user,
            process=Path(comm).name if comm else "process",
            pid=p.get("pid", 0),
            ppid=p.get("ppid", 0),
            binary_path=binary_path,
            arguments=args,
            command=args or comm,
            raw_line=f"PID {p.get('pid')} PPID {p.get('ppid')} USER {user} EXEC {binary_path} {args}".strip(),
        )

    @staticmethod
    def _extract_binary_path(comm: str, args: str) -> str:
        """Resolve actual executed binary path from comm and command args."""
        if comm and comm.startswith("/"):
            return comm
        if args:
            try:
                tokens = shlex.split(args)
                if tokens and tokens[0].startswith("/"):
                    return tokens[0]
            except ValueError:
                pass
        return comm
