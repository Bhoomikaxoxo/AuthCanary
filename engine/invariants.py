"""
AuthCanary — Deterministic Security Invariants Engine.

Replaces numerical point scores with categorical security invariants and
explicit threat classifications:
  - CRITICAL : Active kill-chain correlation, unauthorized SSH keys, config drift
  - WARNING  : Novel sudo commands, first-time sudo user, failed auth bursts
  - NOTICE   : Normal privilege escalation, isolated login failure
  - INFO     : Routine authorization, Touch ID validation, successful logins
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from engine.models import ScoredEvent
from engine.playbooks import get_playbook

if TYPE_CHECKING:
    from ingest.schema import AuthEvent
    from engine.models import EnrichmentResult
    from engine.baseline import Baseline


class InvariantEngine:
    """Evaluates host events against deterministic security predicates."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        correlation_cfg = self.config.get("correlation", {})
        self.sequence_window_min = correlation_cfg.get("sequence_window_min", 15)

    def evaluate(
        self,
        event: AuthEvent,
        enrichment: EnrichmentResult | None,
        baseline: Baseline,
        is_novel: bool = False,
        novelty_reasons: list[str] | None = None,
    ) -> ScoredEvent:
        """Evaluate an AuthEvent and assign explicit severity, invariant tags, and playbook."""
        invariants: list[str] = []
        reasons: list[str] = list(novelty_reasons or [])
        severity = "INFO"
        numeric_score = 0

        user = event.username or "system"
        event_type = event.event_type
        process = event.process or "system"

        # ── Correlation check: Recent user activity for kill chains ──
        recent_events = []
        if hasattr(baseline, "get_recent_user_events"):
            recent_events = baseline.get_recent_user_events(
                user,
                window_minutes=self.sequence_window_min,
                current_timestamp=event.timestamp,
            )

        past_signals = set(s for r in recent_events for s in r.get("signals", []))

        has_prior_remote_access = any(
            s in past_signals
            for s in ("new_asn", "new_ip_new_asn", "novel_remote_origin", "brute_force_burst")
        )

        binary = event.binary_path or (event.command.split()[0] if event.command else "")
        cmd_full = (event.command or "") + " " + (event.arguments or "")
        is_suspicious_path = any(
            binary.startswith(prefix)
            for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/")
        )

        # ── 1. Check for Critical Invariants ───────────────────────

        # Critical: Multi-stage kill chain (Remote Access -> Sudo / Persistence / Suspicious Exec)
        if has_prior_remote_access and (
            event_type in ("sudo_used", "privilege_elevation", "PERSISTENCE_ADDITION", "PERSISTENCE_MODIFIED")
            or process == "sudo"
            or event_type == "ssh_key_added"
            or is_suspicious_path
        ):
            severity = "CRITICAL"
            numeric_score = 100
            invariants.append("KILL_CHAIN_ESCALATION")
            reasons.insert(
                0,
                f"CRITICAL: Action ({event_type or process}) preceded by novel remote access within {self.sequence_window_min}m"
            )

        # Critical: Pipeline execution from network (e.g. curl ... | sh)
        elif any(tool in cmd_full for tool in ("curl ", "wget ")) and any(sh in cmd_full for sh in ("| sh", "| bash", "| zsh", "|python")):
            severity = "CRITICAL"
            numeric_score = 95
            invariants.append("CURL_BASH_EXECUTION")
            reasons.append(f"CRITICAL: Direct shell execution from network pipe: {event.command or event.arguments}")

        # Critical: SSH key injection
        elif event_type == "ssh_key_added":
            severity = "CRITICAL"
            numeric_score = 90
            invariants.append("UNAUTHORIZED_KEY_ADD")
            reasons.append(f"CRITICAL: New SSH authorized key added for user '{user}'")

        # Critical: Persistence modification in system location
        elif event_type == "PERSISTENCE_ADDITION" and any(p in (event.persistence_target or "") for p in ("/Library/LaunchDaemons", "/etc/pam.d")):
            severity = "CRITICAL"
            numeric_score = 85
            invariants.append("PERSISTENCE_INJECTION")
            reasons.append(f"CRITICAL: Root-level persistence item added at '{event.persistence_target}'")

        # ── 2. Check for Warning Invariants ────────────────────────

        # Warning: Suspicious execution path (/tmp, /var/tmp)
        elif is_suspicious_path:
            severity = "WARNING"
            numeric_score = 75
            invariants.append("SUSPICIOUS_EXEC_PATH")
            reasons.append(f"Process executed from suspicious temporary directory: '{binary}'")

        # Warning: Persistence modification in user location
        elif event_type in ("PERSISTENCE_ADDITION", "PERSISTENCE_MODIFIED"):
            severity = "WARNING"
            numeric_score = 70
            invariants.append("PERSISTENCE_MODIFIED")
            reasons.append(f"Persistence modified at '{event.persistence_target}': {event.command or 'file change'}")

        # Warning: Sensitive TCC permission grant (Screen capture, Camera, Mic, Accessibility)
        elif event_type == "PERMISSION_GRANT" and any(s in (event.permission_service or "") for s in ("Camera", "Microphone", "ScreenCapture", "SystemPolicyAllFiles", "Accessibility")):
            # Routine Apple first-party utilities for screenshots and recordings
            is_apple_screenshot_daemon = (
                ("ScreenCapture" in (event.permission_service or "") or "ListenEvent" in (event.permission_service or ""))
                and process in ("screencapture", "screencaptureui", "replayd", "tccd", "ControlCenter", "SystemUIServer")
            )
            if is_apple_screenshot_daemon:
                severity = "NOTICE"
                numeric_score = 20
                invariants.append("SYSTEM_PERMISSION_EVAL")
                reasons.append(f"macOS native screenshot utility '{process}' evaluated '{event.permission_service}'")
            else:
                severity = "WARNING"
                numeric_score = 65
                invariants.append("SENSITIVE_PERMISSION_GRANT")
                reasons.append(f"Sensitive system permission '{event.permission_service}' granted to '{event.process}'")

        elif is_novel and (event_type in ("sudo_used", "privilege_elevation") or process == "sudo"):
            severity = "WARNING"
            numeric_score = 65
            invariants.append("NOVEL_SUDO_COMMAND" if event.command else "FIRST_TIME_SUDO_USER")

        elif event_type == "PROCESS_EXEC" and is_novel:
            severity = "WARNING" if is_novel and user == "root" else "NOTICE"
            numeric_score = 50 if user == "root" else 20
            invariants.append("NOVEL_BINARY_EXECUTION" if is_novel else "PROCESS_EXEC")
            if is_novel and user == "root":
                reasons.append(f"First-seen binary execution under root: '{binary}'")

        elif event_type == "login_success" and is_novel:
            severity = "WARNING"
            numeric_score = 60
            invariants.append("NOVEL_REMOTE_ORIGIN")

        elif event_type == "login_failure":
            # Check for burst / brute-force
            recent_failures = 0
            if hasattr(baseline, "get_recent_failures") and event.source_ip:
                try:
                    event_dt = datetime.fromisoformat(event.timestamp)
                except (ValueError, TypeError):
                    event_dt = datetime.now()
                since_ts = (event_dt - timedelta(minutes=15)).isoformat()
                recent_failures = baseline.get_recent_failures(
                    user, event.source_ip, since=since_ts
                )
            if recent_failures >= 3:
                severity = "WARNING"
                numeric_score = 55
                invariants.append("FAILED_AUTH_BURST")
                reasons.append(f"Multiple consecutive authentication failures ({recent_failures}+) for user '{user}'")
            else:
                severity = "NOTICE"
                numeric_score = 25
                invariants.append("AUTH_FAILURE")
                reasons.append(f"Failed authentication attempt for user '{user}'")

        # ── 3. Check for Notice Invariants ─────────────────────────

        elif event_type in ("sudo_used", "privilege_elevation") or process == "sudo":
            severity = "NOTICE"
            numeric_score = 30
            invariants.append("SUDO_ELEVATION")
            cmd_info = f": {event.command}" if event.command else ""
            reasons.append(f"Privilege elevation (sudo) executed by '{user}'{cmd_info}")

        elif event_type == "PERMISSION_GRANT":
            severity = "NOTICE"
            numeric_score = 20
            invariants.append("PERMISSION_GRANT")
            reasons.append(f"Permission '{event.permission_service}' evaluated for '{event.process}'")

        elif event_type == "PROCESS_EXEC":
            severity = "INFO"
            numeric_score = 5
            invariants.append("PROCESS_EXEC")
            reasons.append(f"Process execution '{binary}' (PID: {event.pid})")

        # ── 4. Routine / Info Invariants ───────────────────────────

        else:
            severity = "INFO"
            numeric_score = 0
            invariants.append("AUTH_SUCCESS")
            if process == "authd" or event.auth_method == "touch_id":
                reasons.append(f"System authorization / Touch ID verified for '{user}'")
            else:
                reasons.append(f"Routine authentication ({event.auth_method or 'system'}) by '{user}'")

        # Incident response playbook guidance
        playbook = get_playbook(
            signals=[s.lower() for s in invariants],
            user=user,
            ip=event.source_ip or "local",
            asn=enrichment.asn if enrichment else "local",
            city=enrichment.city if enrichment else "",
            country=enrichment.country if enrichment else "",
        )

        return ScoredEvent(
            event=event,
            enrichment=enrichment,
            severity=severity,
            invariants=invariants,
            is_novel=is_novel,
            novelty_reasons=reasons,
            score=numeric_score,
            reasons=reasons,
            signals=[s.lower() for s in invariants],
            playbook=playbook,
        )
