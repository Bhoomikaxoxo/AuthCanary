"""
AuthCanary — Real-time System Log Activity Monitor & Web Server.

Serves the macOS Activity Monitor & Console dashboard locally, with:
  - Direct SSE (Server-Sent Events) live log streaming from /usr/bin/log stream
  - Dynamic API endpoints (/api/logs, /api/stats, /api/status)
  - Process breakdown metrics and real-time security invariant tagging
"""

from __future__ import annotations

import json
import os
import platform
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

from ingest.adapters import MacOSUnifiedLogAdapter
from engine.baseline import Baseline
from engine.invariants import InvariantEngine
from engine.novelty import NoveltyTracker
from engine.process_monitor import ProcessMonitor
from engine.persistence_monitor import PersistenceMonitor


class SystemLogStreamer:
    """Streams live macOS Unified Logs or system logs in real-time to connected clients."""

    def __init__(self, db_path: str, config: dict | None = None) -> None:
        self.db_path = db_path
        self.config = config or {}
        self.baseline = Baseline(db_path=db_path)
        self.novelty = NoveltyTracker()
        self.invariants = InvariantEngine(config=self.config)
        self.process_monitor = ProcessMonitor(baseline=self.baseline)
        self.persistence_monitor = PersistenceMonitor(baseline=self.baseline)
        self.subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self._running = False
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._poll_thread: Optional[threading.Thread] = None

    def subscribe(self) -> queue.Queue:
        """Register a new client queue for live log events."""
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Remove a client queue on disconnect."""
        with self._lock:
            self.subscribers.discard(q)

    def broadcast(self, data: dict) -> None:
        """Send a live event to all connected web clients."""
        with self._lock:
            dead = set()
            for q in self.subscribers:
                try:
                    q.put_nowait(data)
                except queue.Full:
                    dead.add(q)
            for d in dead:
                self.subscribers.discard(d)

    def start(self) -> None:
        """Start the background log streaming worker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_stream, daemon=True)
        self._thread.start()
        self._poll_thread = threading.Thread(target=self._run_monitors_poll, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        """Stop streaming and terminate child processes."""
        self._running = False
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _run_monitors_poll(self) -> None:
        """Periodically poll process execution table and persistence paths."""
        try:
            self.process_monitor.initialize_snapshot()
            self.persistence_monitor.initialize_snapshot()
        except Exception:
            pass

        while self._running:
            time.sleep(2.0)
            if not self._running:
                break
            try:
                # 1. Check newly executed processes
                for ev in self.process_monitor.poll():
                    self._process_and_broadcast(ev)

                # 2. Check persistence modifications
                for ev in self.persistence_monitor.scan():
                    self._process_and_broadcast(ev)
            except Exception:
                pass

    def _process_and_broadcast(self, event) -> None:
        """Evaluate and broadcast an AuthEvent from any source to connected web clients."""
        is_novel, novelty_reasons = self.novelty.evaluate(event, None, self.baseline)
        scored = self.invariants.evaluate(
            event=event,
            enrichment=None,
            baseline=self.baseline,
            is_novel=is_novel,
            novelty_reasons=novelty_reasons,
        )
        try:
            self.baseline.record_event(
                event=event,
                enrichment=None,
                score=scored.score,
                reasons=scored.reasons,
                signals=scored.signals,
                severity=scored.severity,
                invariants=scored.invariants,
                is_novel=is_novel,
                command=event.command,
                process=event.process,
            )
        except Exception:
            pass
        self.broadcast(scored.to_dict())

    def _run_stream(self) -> None:
        """Continuously pipe macOS `log stream` or fallback tail."""
        if platform.system() != "Darwin":
            return

        predicate = (
            '(process == "sshd") OR '
            '(process == "sudo") OR '
            '(process == "launchd") OR '
            '(subsystem == "com.apple.Authorization") OR '
            '(subsystem == "com.apple.TCC") OR '
            '(process == "opendirectoryd")'
        )

        cmd = [
            "/usr/bin/log", "stream",
            "--style", "ndjson",
            "--predicate", predicate,
            "--info",
        ]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            sys.stderr.write(f"  [Streamer] Could not spawn log stream: {e}\n")
            return

        for line in iter(self._proc.stdout.readline, ""):
            if not self._running:
                break
            line_str = line.strip()
            if not line_str or not line_str.startswith("{"):
                continue
            try:
                raw_entry = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            # Parse raw JSON entry to AuthEvent
            event = MacOSUnifiedLogAdapter.parse_entry(raw_entry)
            if not event:
                continue

            # Zero-Math Novelty Diff
            is_novel, novelty_reasons = self.novelty.evaluate(event, None, self.baseline)

            # Security Invariants Evaluation
            scored = self.invariants.evaluate(
                event=event,
                enrichment=None,
                baseline=self.baseline,
                is_novel=is_novel,
                novelty_reasons=novelty_reasons,
            )

            # Record event in SQLite baseline
            try:
                self.baseline.record_event(
                    event=event,
                    enrichment=None,
                    score=scored.score,
                    reasons=scored.reasons,
                    signals=scored.signals,
                    severity=scored.severity,
                    invariants=scored.invariants,
                    is_novel=is_novel,
                    command=event.command,
                    process=event.process,
                )
            except Exception:
                pass

            # Broadcast to live dashboard clients
            payload = scored.to_dict()
            self.broadcast(payload)


# Global streamer instance shared across HTTP threads
_STREAMER: Optional[SystemLogStreamer] = None


class AuthCanaryHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the macOS Activity Monitor & Console dashboard."""

    output_dir: Path = Path("./output")
    db_path: str = "~/.authcanary/authcanary.db"

    def log_message(self, format: str, *args) -> None:
        """Suppress routine polling logs to keep console clean."""
        if len(args) > 0:
            path_str = str(args[0])
            if any(k in path_str for k in ("/api/status", "/api/stats", "/api/stream")):
                return
        sys.stderr.write(f"  [HTTP] {self.address_string()} - {format % args}\n")

    def _send_json(self, status: int, data: dict | list) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if not path:
            path = "/"

        # 1. Server Status
        if path == "/api/status":
            report_file = self.output_dir / "report.html"
            mtime = report_file.stat().st_mtime if report_file.exists() else None
            status_payload = {
                "server": "AuthCanary macOS Activity Monitor",
                "status": "online",
                "platform": f"{platform.system()} {platform.machine()}",
                "stream_active": _STREAMER._running if _STREAMER else False,
                "subscribers": len(_STREAMER.subscribers) if _STREAMER else 0,
                "report_exists": report_file.exists(),
                "report_mtime": mtime,
            }
            self._send_json(200, status_payload)
            return

        # 2. Historical / Recent Logs from SQLite
        if path == "/api/logs":
            baseline = Baseline(db_path=self.db_path)
            events = baseline.get_all_logged_events(limit=250)
            self._send_json(200, events)
            return

        # 3. Process Breakdown Statistics
        if path == "/api/stats":
            baseline = Baseline(db_path=self.db_path)
            stats = baseline.get_process_stats()
            self._send_json(200, stats)
            return

        # 4. Real-time Live Log Stream (Server-Sent Events)
        if path == "/api/stream":
            if not _STREAMER:
                self.send_error(503, "Log streamer is not active")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            client_queue = _STREAMER.subscribe()
            try:
                # Send initial connection confirmation
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()

                while True:
                    try:
                        # Wait for an event with timeout for keep-alive comments
                        event_data = client_queue.get(timeout=10)
                        payload = f"data: {json.dumps(event_data, default=str)}\n\n"
                        self.wfile.write(payload.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Send keep-alive ping comment to prevent socket timeout
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                _STREAMER.unsubscribe(client_queue)
            return

        # 5. Raw JSON Report
        if path == "/report.json":
            json_file = self.output_dir / "report.json"
            if json_file.exists():
                body = json_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404, "report.json not found")
            return

        # 6. Main Activity Monitor Dashboard
        if path in ("/", "/index.html", "/report.html"):
            report_file = self.output_dir / "report.html"
            if not report_file.exists():
                placeholder = (
                    "<!DOCTYPE html><html><head><title>AuthCanary Activity Monitor</title>"
                    "<style>body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0c0f17; color: #f8fafc; text-align: center; padding: 5rem 1rem; }"
                    "h1 { color: #06b6d4; } code { background: #1a2234; padding: 0.2rem 0.5rem; border-radius: 4px; }</style>"
                    "</head><body>"
                    "<h1>AuthCanary Activity Monitor</h1>"
                    "<p>Initializing real-time system log monitor...</p>"
                    "<p>Run <code>python main.py</code> to seed baseline from system logs.</p>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(placeholder)))
                self.end_headers()
                self.wfile.write(placeholder)
                return

            auto_refresh_script = (
                "\n<!-- AuthCanary Live Refresh Hook -->\n"
                "<script>\n"
                "  (function() {\n"
                "    let lastMtime = null;\n"
                "    async function checkUpdate() {\n"
                "      try {\n"
                "        const res = await fetch('/api/status', { cache: 'no-store' });\n"
                "        if (res.ok) {\n"
                "          const data = await res.json();\n"
                "          if (lastMtime === null) {\n"
                "            lastMtime = data.report_mtime;\n"
                "          } else if (data.report_mtime && data.report_mtime !== lastMtime) {\n"
                "            // Do not force reload if SSE stream is actively connected\n"
                "            if (!window.eventSource || window.eventSource.readyState !== 1) {\n"
                "              window.location.reload();\n"
                "            }\n"
                "          }\n"
                "        }\n"
                "      } catch (err) {}\n"
                "    }\n"
                "    setInterval(checkUpdate, 4000);\n"
                "  })();\n"
                "</script>\n"
                "</body>\n"
            )

            content = report_file.read_text(encoding="utf-8")
            if "</body>" in content:
                content = content.replace("</body>", auto_refresh_script)
            else:
                content += auto_refresh_script
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Fallback 404
        self.send_error(404, "Not Found")


def start_server(
    output_dir: Path | str = "./output",
    port: int = 8080,
    host: str = "127.0.0.1",
    open_browser: bool = False,
    db_path: str = "~/.authcanary/authcanary.db",
    config: dict | None = None,
) -> None:
    """Start local threaded HTTP server with real-time log streaming."""
    global _STREAMER

    resolved_dir = Path(output_dir).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    expanded_db = str(Path(db_path).expanduser())

    AuthCanaryHandler.output_dir = resolved_dir
    AuthCanaryHandler.db_path = expanded_db

    # Initialize and start live system log streamer
    _STREAMER = SystemLogStreamer(db_path=expanded_db, config=config or {})
    _STREAMER.start()

    server_address = (host, port)
    try:
        httpd = ThreadingHTTPServer(server_address, AuthCanaryHandler)
    except OSError as e:
        print(f"✗ Could not start server on {host}:{port} — {e}")
        if _STREAMER:
            _STREAMER.stop()
        sys.exit(1)

    url = f"http://{host}:{port}/"
    print("  ══════════════════════════════════════════════════════════════════")
    print(f"  AuthCanary macOS Activity Monitor & Console active")
    print(f"  URL:             {url}")
    print(f"  Live Streaming:  Real-time (/usr/bin/log stream ndjson)")
    print(f"  Monitored:       sudo, authd (Touch ID), sshd, tcc, opendirectoryd")
    print("  ══════════════════════════════════════════════════════════════════")
    print("  Press Ctrl+C to stop.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopping AuthCanary Activity Monitor server...")
        if _STREAMER:
            _STREAMER.stop()
        httpd.server_close()
        print("  Server stopped.")
