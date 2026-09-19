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
from engine.scoring import Scorer
from engine.models import ScoredEvent
from output.report import generate_report
from output.alerts import get_channels
from output.server import start_server
from engine.integrity import IntegrityChecker


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

    # ── Scoring ────────────────────────────────────────────────────
    scorer = Scorer(config)
    warmed_up = args.skip_warmup or baseline.is_warmed_up()

    if not warmed_up:
        print(f"\n  {baseline.warmup_status()}")

    scored_events: list[ScoredEvent] = []
    alert_events: list[ScoredEvent] = []

    for event in events:
        # Enrich IP if available
        enrichment = None
        if enrichment_cache and event.source_ip:
            enrichment = enrichment_cache.lookup(event.source_ip)

        # Score against baseline (evaluates individual signals + correlated sequences)
        scored = scorer.score(event, enrichment, baseline)

        # Record in baseline (learn from this event, saving structured signals)
        if not args.dry_run:
            baseline.record_event(
                event, enrichment, scored.score, scored.reasons, signals=scored.signals,
            )

        # Only collect alerts if past warm-up
        if scored.score > 0:
            scored_events.append(scored)
            if warmed_up and scorer.is_alert(scored):
                alert_events.append(scored)

    # ── Output ─────────────────────────────────────────────────────
    if not args.dry_run:
        json_path, html_path = generate_report(
            scored_events, baseline, config, args.skip_warmup, integrity_results=integrity_results,
        )
        print(f"\n  Report: {html_path}")
        print(f"  JSON:   {json_path}")
    else:
        print("\n  [dry-run] Skipping report generation and baseline update.")

    # ── Alerts ─────────────────────────────────────────────────────
    if (alert_events or drift_alerts) and warmed_up:
        channels = get_channels(config)
        total_alerts = len(alert_events) + len(drift_alerts)
        print(f"\n  🚨 {total_alerts} alert(s) ({len(alert_events)} auth, {len(drift_alerts)} integrity):\n")
        for ch in channels:
            for ae in alert_events:
                ch.send(ae)
    elif warmed_up:
        print("\n  ✓ No anomalies above threshold.")

    # ── Save cursor ────────────────────────────────────────────────
    if not args.dry_run:
        cursor_mgr.save(new_cursor)

    # Summary
    print(f"\n  Summary: {len(events)} events processed, "
          f"{len(scored_events)} scored, "
          f"{len(alert_events)} auth alerts, "
          f"{len(drift_alerts)} drift alerts.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="authcanary",
        description=(
            "AuthCanary — Local-first anomaly detection for auth logs. "
            "Builds a statistical baseline and surfaces only genuinely "
            "novel events."
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
        help="Bypass warm-up period, score all events immediately",
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
        help="Start local HTTP server for live dashboard viewing and auto-refresh",
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
        print("AuthCanary v1\n")
        config = load_config(args.config)
        output_dir = config.get("output", {}).get("directory", "./output")
        start_server(
            output_dir=output_dir,
            port=args.port,
            host=args.bind,
            open_browser=args.open,
        )
        sys.exit(0)

    print("AuthCanary v1\n")
    run(args)


if __name__ == "__main__":
    main()
