"""
AuthCanary — Local dashboard web server.

Serves output/report.html and report.json locally with live-reloading
capabilities so security operators can monitor incoming log anomalies.
"""

from __future__ import annotations

import json
import os
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional


# Minimal script injected into HTML when served by AuthCanary server
# to enable automatic dashboard reloading when the report is re-generated.
_AUTO_REFRESH_SCRIPT = """
<!-- AuthCanary Live Refresh Hook -->
<script>
  (function() {
    let lastMtime = null;
    async function checkUpdate() {
      try {
        const res = await fetch('/api/status', { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          if (lastMtime === null) {
            lastMtime = data.report_mtime;
          } else if (data.report_mtime && data.report_mtime !== lastMtime) {
            console.log('[AuthCanary] Report updated, reloading dashboard...');
            window.location.reload();
          }
        }
      } catch (err) {
        // Server temporarily down or unreachable
      }
    }
    setInterval(checkUpdate, 4000);
  })();
</script>
</body>
"""


class AuthCanaryHandler(BaseHTTPRequestHandler):
    """HTTP handler serving AuthCanary dashboard reports with live refresh."""

    output_dir: Path = Path("./output")

    def log_message(self, format: str, *args) -> None:
        """Custom concise log formatting."""
        # Suppress routine status checks to keep terminal output clean
        if len(args) > 0 and "/api/status" in str(args[0]):
            return
        sys.stderr.write(f"  [HTTP] {self.address_string()} - {format % args}\n")

    def _send_response(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if not path:
            path = "/"

        if path == "/api/status":
            report_file = self.output_dir / "report.html"
            mtime = report_file.stat().st_mtime if report_file.exists() else None
            status_payload = {
                "server": "AuthCanary Dashboard Server",
                "status": "online",
                "report_exists": report_file.exists(),
                "report_mtime": mtime,
            }
            body = json.dumps(status_payload).encode("utf-8")
            self._send_response(200, "application/json; charset=utf-8", body)
            return

        if path in ("/", "/index.html", "/report.html"):
            report_file = self.output_dir / "report.html"
            if not report_file.exists():
                placeholder = (
                    "<!DOCTYPE html><html><head><title>AuthCanary</title>"
                    "<style>body { font-family: sans-serif; background: #07090e; color: #f8fafc; text-align: center; padding: 5rem 1rem; }"
                    "h1 { color: #06b6d4; } code { background: #121826; padding: 0.2rem 0.5rem; border-radius: 4px; }</style>"
                    "</head><body>"
                    "<h1>AuthCanary Dashboard</h1>"
                    "<p>No report generated yet.</p>"
                    "<p>Run <code>python main.py</code> to analyze logs and generate <code>output/report.html</code>.</p>"
                    "<p>This page will automatically refresh once a report is available.</p>"
                    + _AUTO_REFRESH_SCRIPT +
                    "</html>"
                ).encode("utf-8")
                self._send_response(200, "text/html; charset=utf-8", placeholder)
                return

            content = report_file.read_text(encoding="utf-8")
            # Inject live refresh before closing body tag
            if "</body>" in content:
                content = content.replace("</body>", _AUTO_REFRESH_SCRIPT)
            else:
                content += _AUTO_REFRESH_SCRIPT

            self._send_response(200, "text/html; charset=utf-8", content.encode("utf-8"))
            return

        if path == "/report.json":
            json_file = self.output_dir / "report.json"
            if json_file.exists():
                body = json_file.read_bytes()
                self._send_response(200, "application/json; charset=utf-8", body)
                return
            self._send_response(404, "application/json", b'{"error": "report.json not found"}')
            return

        # Fallback 404
        self._send_response(404, "text/plain", b"404 Not Found")


def start_server(
    output_dir: Path | str = "./output",
    port: int = 8080,
    host: str = "127.0.0.1",
    open_browser: bool = False,
) -> None:
    """Start local HTTP server for AuthCanary dashboard."""
    resolved_dir = Path(output_dir).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)

    AuthCanaryHandler.output_dir = resolved_dir

    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, AuthCanaryHandler)
    except OSError as e:
        print(f"✗ Could not start server on {host}:{port} — {e}")
        sys.exit(1)

    url = f"http://{host}:{port}/"
    print("  ══════════════════════════════════════════════════════════════")
    print(f"  AuthCanary Dashboard Server active")
    print(f"  URL:           {url}")
    print(f"  Output Dir:    {resolved_dir}")
    print(f"  Live Refresh:  Enabled (auto-detects regenerated reports)")
    print("  ══════════════════════════════════════════════════════════════")
    print("  Press Ctrl+C to stop the server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopping AuthCanary dashboard server...")
        httpd.server_close()
        print("  Server stopped.")
