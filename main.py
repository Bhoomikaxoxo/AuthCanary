#!/usr/bin/env python3
"""
AuthCanary — CLI entry point.

Pipeline: detect adapter → read events → enrich IPs → score against
baseline → update baseline → generate report → fire alerts → save cursor.

Usage:
    python main.py [--config CONFIG] [--skip-warmup] [--log-source PATH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from ingest.adapters import get_adapter
from ingest.cursor import CursorManager
from enrich.providers import get_provider
from enrich.cache import EnrichmentCache
from engine.baseline import Baseline
from engine.invariants import InvariantEngine
from engine.novelty import NoveltyTracker
from engine.models import ScoredEvent
from output.report import generate_report
from output.alerts import get_channels
from output.server import start_server
from engine.integrity import IntegrityChecker
from engine.persistence_monitor import PersistenceMonitor


def load_config(config_path: str) -> dict:
    """Load and return the YAML config file."""
    path = Path(config_path)
    if not path.exists():
        print(f"⚠ Config file not found: {config_path}")
        print("  Using defaults. Create config.yaml to customize.")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run(args: argparse.Namespace) -> None:
    """Main pipeline execution."""
    config = load_config(args.config)

    # ── Resolve paths ──────────────────────────────────────────────
    storage_cfg = config.get("storage", {})
    db_path = str(Path(storage_cfg.get("db_path", "~/.authcanary/authcanary.db")).expanduser())
    cursor_path = storage_cfg.get("cursor_path", "~/.authcanary/cursor.json")

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    # ── Reset baseline if requested ────────────────────────────────
    warmup_cfg = config.get("warmup", {})
    baseline = Baseline(
        db_path=db_path,
        warmup_days=warmup_cfg.get("days", 7),
        warmup_min_events=warmup_cfg.get("min_events", 50),
    )

    if args.reset_baseline:
        baseline.reset()
        CursorManager(cursor_path).reset()
        print("✓ Baseline and cursor reset. Starting fresh.")

    # ── Ingestion ──────────────────────────────────────────────────
    log_source = args.log_source or config.get("log_source", {}).get("path", "auto")
    try:
        adapter = get_adapter(log_source)
    except RuntimeError as e:
        print(f"✗ {e}")
        sys.exit(1)

    print(f"  Adapter: {type(adapter).__name__}")

    cursor_mgr = CursorManager(cursor_path)
    cursor = cursor_mgr.load()
    events, new_cursor = adapter.read_events(cursor)

    # ── File Integrity Monitoring (FIM) ────────────────────────────
    integrity_cfg = config.get("integrity", {})
    integrity_results = []
    drift_alerts = []
    if integrity_cfg.get("enabled", True):
        targets = integrity_cfg.get("targets")
        checker = IntegrityChecker(db_path=db_path, targets=targets)
        integrity_results = checker.check(dry_run=args.dry_run)
        drift_alerts = [r for r in integrity_results if r.is_alert]
        denied = [r for r in integrity_results if r.status == "PERMISSION_DENIED"]

        if drift_alerts:
            print(f"  🚨 Integrity: {len(drift_alerts)} configuration drift alert(s) detected!")
            for da in drift_alerts:
                print(f"     • {da.message}")
        elif denied:
            print(f"  Integrity: {len(integrity_results)} target(s) monitored ({len(denied)} permission denied)")
        else:
            print(f"  Integrity: {len(integrity_results)} target(s) monitored (0 drift)")

    # ── Persistence Monitoring ─────────────────────────────────────
    persistence_mon = PersistenceMonitor(baseline=baseline)
    pers_events = persistence_mon.scan()
    if pers_events:
        print(f"  🚨 Persistence: {len(pers_events)} new or modified persistence item(s) detected!")
        events.extend(pers_events)

    if not events:
        print("  No new events to process.")
        # Still generate a report with current stats and integrity results
        json_path, html_path = generate_report(
            [], baseline, config, args.skip_warmup, integrity_results=integrity_results,
        )
        print(f"\n  Report: {html_path}")
        cursor_mgr.save(new_cursor)
        return

    print(f"  Ingested {len(events)} new events.")

    # ── Enrichment ─────────────────────────────────────────────────
    enrich_cfg = config.get("enrichment", {})
    enrichment_cache = None

    if enrich_cfg.get("enabled", True):
        try:
            provider = get_provider(
                enrich_cfg.get("provider", "ip-api"),
                rate_limit_per_min=enrich_cfg.get("rate_limit_per_min", 45),
            )
            enrichment_cache = EnrichmentCache(
                db_path=db_path,
                provider=provider,
                ttl_days=enrich_cfg.get("cache_ttl_days", 30),
            )
            print("  Enrichment: enabled (ip-api.com)")
        except Exception as e:
            print(f"  Enrichment: disabled ({e})")

    # ── Evaluation (Novelty & Security Invariants) ─────────────────
    novelty = NoveltyTracker()
    invariants = InvariantEngine(config)
    alert_severities = set(config.get("invariants", {}).get("alert_severities", ["CRITICAL", "WARNING"]))

    all_scored_events: list[ScoredEvent] = []
    alert_events: list[ScoredEvent] = []

    for event in events:
        enrichment = None
        if enrichment_cache and event.source_ip:
            enrichment = enrichment_cache.lookup(event.source_ip)

        is_novel, novelty_reasons = novelty.evaluate(event, enrichment, baseline)
        scored = invariants.evaluate(
            event=event,
            enrichment=enrichment,
            baseline=baseline,
            is_novel=is_novel,
            novelty_reasons=novelty_reasons,
        )

        # Record in baseline
        if not args.dry_run:
            baseline.record_event(
                event=event,
                enrichment=enrichment,
                score=scored.score,
                reasons=scored.reasons,
                signals=scored.signals,
                severity=scored.severity,
                invariants=scored.invariants,
                is_novel=is_novel,
                command=event.command,
                process=event.process,
            )

        all_scored_events.append(scored)

        if scored.severity in alert_severities:
            alert_events.append(scored)

    # ── Output ─────────────────────────────────────────────────────
    if not args.dry_run:
        json_path, html_path = generate_report(
            alert_events, baseline, config, args.skip_warmup, integrity_results=integrity_results,
            all_events=all_scored_events,
        )
        print(f"\n  Report: {html_path}")
        print(f"  JSON:   {json_path}")
    else:
        print("\n  [dry-run] Skipping report generation and baseline update.")

    # ── Alerts ─────────────────────────────────────────────────────
    if (alert_events or drift_alerts):
        channels = get_channels(config)
        total_alerts = len(alert_events) + len(drift_alerts)
        print(f"\n  🚨 {total_alerts} security alert(s) ({len(alert_events)} auth/elevations, {len(drift_alerts)} integrity):\n")
        for ch in channels:
            for ae in alert_events:
                ch.send(ae)
    else:
        print("\n  ✓ No security invariants violated.")

    # ── Save cursor ────────────────────────────────────────────────
    if not args.dry_run:
        cursor_mgr.save(new_cursor)

    # Summary
    print(f"\n  Summary: {len(events)} real system events processed, "
          f"{len(alert_events)} warnings/critical alerts, "
          f"{len(drift_alerts)} drift alerts.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="authcanary",
        description=(
            "AuthCanary — macOS System Log & Security Activity Monitor. "
            "Evaluates real system logs against deterministic security invariants."
        ),
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument(
        "--skip-warmup",
        action="store_true",
        help="Bypass warm-up period, alert on all events immediately",
    )
    parser.add_argument(
        "--reset-baseline",
        action="store_true",
        help="Wipe baseline DB and cursor, start fresh",
    )
    parser.add_argument(
        "--log-source",
        default=None,
        help="Override log source (file path, 'journald', or 'auto')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Process events but don't update baseline or write reports",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start live macOS Activity Monitor & Console web server",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for local dashboard server (default: 8080)",
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Bind address for local dashboard server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open web browser on launch",
    )

    args = parser.parse_args()

    if args.serve:
        print("AuthCanary — macOS System Log Activity Monitor\n")
        config = load_config(args.config)
        output_dir = config.get("output", {}).get("directory", "./output")
        storage_cfg = config.get("storage", {})
        db_path = str(Path(storage_cfg.get("db_path", "~/.authcanary/authcanary.db")).expanduser())
        start_server(
            output_dir=output_dir,
            port=args.port,
            host=args.bind,
            open_browser=args.open,
            db_path=db_path,
            config=config,
        )
        sys.exit(0)

    print("AuthCanary — macOS System Log Activity Monitor\n")
    run(args)


if __name__ == "__main__":
    main()
