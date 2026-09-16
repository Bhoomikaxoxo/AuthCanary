"""
SentinelLog — Report generation.

Produces two outputs each run:
  1. report.json  — machine-readable, full detail
  2. report.html  — static HTML dashboard (Jinja2-rendered)

Both go to the configured output directory.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from engine.models import ScoredEvent
from engine.baseline import Baseline


def generate_report(
    scored_events: list[ScoredEvent],
    baseline: Baseline,
    config: dict,
    skip_warmup: bool = False,
) -> tuple[Path, Path]:
    """Generate report.json and report.html.

    Args:
        scored_events: events that scored above 0 (sorted by score desc).
        baseline: the Baseline instance (for stats).
        config: full config dict.
        skip_warmup: whether warm-up was bypassed.

    Returns:
        (path_to_json, path_to_html)
    """
    output_dir = Path(config.get("output", {}).get("directory", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = baseline.get_stats()
    warmup_complete = skip_warmup or baseline.is_warmed_up()
    alert_threshold = config.get("scoring", {}).get("alert_threshold", 60)

    # Sort by score descending
    scored_events.sort(key=lambda se: se.score, reverse=True)

    # Filter to events above threshold for the report (but include all scored > 0)
    anomaly_count = sum(1 for se in scored_events if se.score >= alert_threshold)

    # ── JSON report ────────────────────────────────────────────────
    report_data = {
        "generated_at": datetime.now().isoformat(),
        "warmup_complete": warmup_complete,
        "warmup_message": baseline.warmup_status(),
        "alert_threshold": alert_threshold,
        "anomaly_count": anomaly_count,
        "stats": stats,
        "scored_events": [se.to_dict() for se in scored_events],
    }

    json_path = output_dir / "report.json"
    json_path.write_text(
        json.dumps(report_data, indent=2, default=str),
        encoding="utf-8",
    )

    # ── HTML report ────────────────────────────────────────────────
    template_dir = Path(__file__).parent
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )
    template = env.get_template("template.html")

    # ── Prepare rich template data ─────────────────────────────────
    import platform
    import socket

    host_info = {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.machine()}",
        "os": platform.system(),
        "arch": platform.machine(),
    }

    # Build template context with objects that support attribute access
    class _Obj:
        """Lightweight namespace for Jinja2 dot access."""
        def __init__(self, d: dict):
            for k, v in d.items():
                if isinstance(v, dict):
                    setattr(self, k, _Obj(v))
                elif isinstance(v, list):
                    setattr(self, k, [_Obj(item) if isinstance(item, dict) else item for item in v])
                else:
                    setattr(self, k, v)

    # 1. Alert events (What's Important / Critical Triage)
    alert_events_raw = [se for se in scored_events if se.score >= alert_threshold]

    # 2. All events (Systematic Log Explorer)
    template_all_events = []
    user_stats = {}
    event_type_counts = {}
    hour_histogram = [0] * 24

    for se in scored_events:
        obj = _Obj({
            "score": se.score,
            "reasons": se.reasons,
            "event": _Obj(se.event.to_dict()),
            "enrichment": _Obj(se.enrichment.to_dict()) if se.enrichment else None,
        })
        template_all_events.append(obj)

        u = se.event.username or "unknown"
        if u not in user_stats:
            user_stats[u] = {"count": 0, "max_score": 0, "anomalies": 0}
        user_stats[u]["count"] += 1
        user_stats[u]["max_score"] = max(user_stats[u]["max_score"], se.score)
        if se.score >= alert_threshold:
            user_stats[u]["anomalies"] += 1

        etype = se.event.event_type
        event_type_counts[etype] = event_type_counts.get(etype, 0) + 1

        try:
            h = datetime.fromisoformat(se.event.timestamp).hour
            hour_histogram[h] += 1
        except Exception:
            pass

    template_alert_events = [se for se in template_all_events if se.score >= alert_threshold]
    max_score = max((se.score for se in scored_events), default=0)

    if max_score >= 60:
        threat_level = "CRITICAL"
        threat_label = "Critical Threat Detected"
    elif max_score >= alert_threshold:
        threat_level = "ELEVATED"
        threat_label = "Elevated Anomaly Alert"
    elif max_score > 0:
        threat_level = "MODERATE"
        threat_label = "Minor Signal Deviation"
    else:
        threat_level = "NOMINAL"
        threat_label = "All Systems Nominal"

    html_content = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        warmup_complete=warmup_complete,
        warmup_message=baseline.warmup_status(),
        anomaly_count=anomaly_count,
        alert_threshold=alert_threshold,
        max_score=max_score,
        threat_level=threat_level,
        threat_label=threat_label,
        host_info=_Obj(host_info),
        stats=_Obj(stats),
        user_stats={k: _Obj(v) for k, v in user_stats.items()},
        event_type_counts=event_type_counts,
        hour_histogram=hour_histogram,
        scored_events=template_alert_events,       # Backwards compatible: alert events for "What's Important"
        all_events=template_all_events,            # Full list for "Systematic Log Stream"
    )

    html_path = output_dir / "report.html"
    html_path.write_text(html_content, encoding="utf-8")

    return json_path, html_path
