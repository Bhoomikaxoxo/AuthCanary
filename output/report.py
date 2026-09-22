"""
AuthCanary — Report generation.

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
from engine.playbooks import get_playbook


def generate_report(
    scored_events: list[ScoredEvent],
    baseline: Baseline,
    config: dict,
    skip_warmup: bool = False,
    integrity_results: list | None = None,
    all_events: list[ScoredEvent] | None = None,
) -> tuple[Path, Path]:
    """Generate report.json and report.html.

    Args:
        scored_events: events that scored above 0 (sorted by score desc).
        baseline: the Baseline instance (for stats).
        config: full config dict.
        skip_warmup: whether warm-up was bypassed.
        integrity_results: optional list of IntegrityResult objects from FIM.

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
    integrity_list = integrity_results or []
    integrity_alerts = sum(1 for ir in integrity_list if getattr(ir, "is_alert", False))

    # ── JSON report ────────────────────────────────────────────────
    report_data = {
        "generated_at": datetime.now().isoformat(),
        "warmup_complete": warmup_complete,
        "warmup_message": baseline.warmup_status(),
        "alert_threshold": alert_threshold,
        "anomaly_count": anomaly_count,
        "integrity_alerts": integrity_alerts,
        "stats": stats,
        "integrity": [ir.to_dict() for ir in integrity_list],
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

    # 2. All events (Full Log Stream — includes score-0 events)
    # Prefer persisted history from baseline event_log if available, else use passed events
    logged_events = baseline.get_all_logged_events(limit=1000) if hasattr(baseline, "get_all_logged_events") else []
    template_all_events = []
    user_stats = {}
    event_type_counts = {}
    hour_histogram = [0] * 24

    if logged_events:
        for le in logged_events:
            sigs = le.get("signals", [])
            invs = le.get("invariants", [])
            pb = get_playbook(sigs or [i.lower() for i in invs], user=le["username"], ip=le.get("source_ip") or "unknown")
            obj = _Obj({
                "score": le["score"],
                "reasons": le["reasons"],
                "severity": le.get("severity", "INFO"),
                "invariants": invs,
                "process": le.get("process", "system"),
                "is_novel": le.get("is_novel", False),
                "command": le.get("command", ""),
                "event": _Obj({
                    "timestamp": le["timestamp"],
                    "username": le["username"],
                    "event_type": le["event_type"],
                    "source_ip": le["source_ip"],
                    "raw_line": le["raw_line"],
                    "process": le.get("process", "system"),
                    "command": le.get("command", ""),
                }),
                "enrichment": None,
                "playbook": pb,
            })
            template_all_events.append(obj)
    else:
        full_events = all_events if all_events is not None else scored_events
        for se in full_events:
            sigs = getattr(se, "signals", [])
            invs = getattr(se, "invariants", [])
            pb = getattr(se, "playbook", "") or get_playbook(sigs, user=se.event.username, ip=se.event.source_ip or "unknown")
            obj = _Obj({
                "score": se.score,
                "reasons": se.reasons,
                "severity": getattr(se, "severity", "INFO"),
                "invariants": invs,
                "process": getattr(se.event, "process", "system"),
                "is_novel": getattr(se, "is_novel", False),
                "command": getattr(se.event, "command", ""),
                "event": _Obj(se.event.to_dict()),
                "enrichment": _Obj(se.enrichment.to_dict()) if se.enrichment else None,
                "playbook": pb,
            })
            template_all_events.append(obj)

    # Build 24-hour histogram, hourly max scores, and hourly summary data
    hour_histogram = [0] * 24
    hourly_max_score = [0] * 24
    hourly_reasons = [""] * 24
    flagged_hours = {}

    for obj in template_all_events:
        u = obj.event.username or "unknown"
        if u not in user_stats:
            user_stats[u] = {"count": 0, "max_score": 0, "anomalies": 0}
        user_stats[u]["count"] += 1
        user_stats[u]["max_score"] = max(user_stats[u]["max_score"], obj.score)
        if obj.score >= alert_threshold:
            user_stats[u]["anomalies"] += 1

        etype = obj.event.event_type
        event_type_counts[etype] = event_type_counts.get(etype, 0) + 1

        try:
            h = datetime.fromisoformat(obj.event.timestamp).hour
            hour_histogram[h] += 1
            if obj.score > hourly_max_score[h]:
                hourly_max_score[h] = obj.score
                if obj.reasons:
                    hourly_reasons[h] = obj.reasons[0]
            if obj.score > 0:
                if h not in flagged_hours or obj.score > flagged_hours[h]["score"]:
                    flagged_hours[h] = {
                        "score": obj.score,
                        "reason": obj.reasons[0] if obj.reasons else "Deviation signal",
                        "username": obj.event.username,
                    }
        except Exception:
            pass

    hourly_data = []
    for h in range(24):
        cnt = hour_histogram[h]
        sc = hourly_max_score[h]
        is_anom = sc >= alert_threshold
        hourly_data.append(_Obj({
            "hour": h,
            "count": cnt,
            "max_score": sc,
            "is_anomaly": is_anom,
            "reason": hourly_reasons[h],
        }))

    template_alert_events = [se for se in template_all_events if se.score >= alert_threshold]
    template_flagged_events = [se for se in template_all_events if 0 < se.score < alert_threshold]
    max_score = max((se.score for se in template_all_events), default=0)
    anomaly_count = len(template_alert_events)

    login_count = sum(c for k, c in event_type_counts.items() if "login" in k.lower())
    sudo_count = sum(c for k, c in event_type_counts.items() if "sudo" in k.lower())
    ssh_count = sum(c for k, c in event_type_counts.items() if "ssh" in k.lower() or "key" in k.lower())
    filter_counts = {
        "all": len(template_all_events),
        "anomalies": anomaly_count,
        "flagged": len(template_flagged_events),
        "login": login_count,
        "sudo": sudo_count,
        "ssh": ssh_count,
    }

    if hasattr(baseline, "get_warmup_info"):
        warmup_info = baseline.get_warmup_info()
    else:
        warmup_info = {
            "warmup_complete": warmup_complete,
            "days_elapsed": 0,
            "days_total": 7,
            "days_left": 7,
            "events_processed": len(template_all_events),
            "min_events": 50,
            "events_left": max(0, 50 - len(template_all_events)),
            "event_quota_met": len(template_all_events) >= 50,
            "time_quota_met": False,
        }
    if skip_warmup:
        warmup_info["warmup_complete"] = True
        warmup_complete = True

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

    max_h = max(max(hour_histogram, default=0), 1)
    process_stats = baseline.get_process_stats() if hasattr(baseline, "get_process_stats") else {}

    html_content = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        warmup_complete=warmup_complete,
        warmup_message=baseline.warmup_status(),
        warmup_info=_Obj(warmup_info),
        anomaly_count=anomaly_count,
        alert_threshold=alert_threshold,
        max_score=max_score,
        threat_level=threat_level,
        threat_label=threat_label,
        host_info=_Obj(host_info),
        stats=_Obj(stats),
        process_stats=process_stats,
        user_stats={k: _Obj(v) for k, v in user_stats.items()},
        event_type_counts=event_type_counts,
        filter_counts=_Obj(filter_counts),
        hour_histogram=hour_histogram,
        hourly_data=hourly_data,
        max_h=max_h,
        flagged_hours={k: _Obj(v) for k, v in flagged_hours.items()},
        scored_events=template_alert_events,       # Alert events for "What's Important"
        flagged_events=template_flagged_events,     # Sub-threshold scored events
        all_events=template_all_events,            # Full list for "Systematic Log Stream"
        integrity_results=[_Obj(ir.to_dict()) for ir in integrity_list],
        integrity_alerts=integrity_alerts,
    )

    html_path = output_dir / "report.html"
    html_path.write_text(html_content, encoding="utf-8")

    return json_path, html_path
