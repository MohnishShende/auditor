"""
Self-hosted lightweight Web Dashboard for Linux Server Audit.
Operates unprivileged, allowing audit triggering, report browsing, and drift comparison.
"""

from __future__ import annotations
import html
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import threading
import time
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..cli.audit import AuditOrchestrator
from ..core.snapshot import SnapshotManager
from ..analysis.drift import compare_snapshots


class AuditWebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Server Audit web dashboard."""

    base_dir: Path = Path("audits")
    is_auditing: bool = False
    last_audit_message: str = ""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logging
        pass

    def send_json_response(self, data: Any, status: int = 200) -> None:
        response_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def send_html_response(self, html_content: str, status: int = 200) -> None:
        response_bytes = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        sm = SnapshotManager(self.base_dir)

        if path == "/":
            snapshots = sm.list_snapshots()
            latest = snapshots[0] if snapshots else None
            html_page = self.render_dashboard(snapshots, latest)
            self.send_html_response(html_page)

        elif path == "/api/snapshots":
            self.send_json_response(sm.list_snapshots())

        elif path.startswith("/api/snapshot/"):
            snap_name = path.replace("/api/snapshot/", "").strip("/")
            if "/md" in snap_name:
                snap_id = snap_name.replace("/md", "")
                md_path = self.base_dir / snap_id / "audit.md"
                if md_path.exists():
                    with open(md_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/markdown; charset=utf-8")
                    self.send_header("Content-Disposition", f"attachment; filename=audit-{snap_id}.md")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                    return
                self.send_response(404)
                self.end_headers()
                return
            elif "/html" in snap_name:
                snap_id = snap_name.replace("/html", "")
                h_path = self.base_dir / snap_id / "audit.html"
                if h_path.exists():
                    with open(h_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.send_html_response(content)
                    return
                self.send_response(404)
                self.end_headers()
                return
            else:
                data = sm.load_snapshot(snap_name)
                if data:
                    self.send_json_response(data)
                else:
                    self.send_json_response({"error": "Snapshot not found"}, status=404)

        elif path == "/api/diff":
            snap_a = query.get("a", [None])[0]
            snap_b = query.get("b", [None])[0]
            if not snap_a or not snap_b:
                self.send_json_response({"error": "Missing 'a' or 'b' query parameters"}, status=400)
                return
            data_a = sm.load_snapshot(snap_a)
            data_b = sm.load_snapshot(snap_b)
            if not data_a or not data_b:
                self.send_json_response({"error": "One or both snapshots could not be loaded"}, status=404)
                return
            drift = compare_snapshots(data_a, data_b)
            self.send_json_response(drift)

        elif path == "/api/status":
            self.send_json_response({
                "is_auditing": AuditWebHandler.is_auditing,
                "message": AuditWebHandler.last_audit_message,
            })

        else:
            self.send_html_response("<h1>404 Not Found</h1>", status=404)

    def do_POST(self) -> None:
        if self.path == "/api/audit/run":
            if AuditWebHandler.is_auditing:
                self.send_json_response({"status": "busy", "message": "Audit is already in progress"}, status=409)
                return

            def background_worker():
                AuditWebHandler.is_auditing = True
                AuditWebHandler.last_audit_message = "Audit running..."
                try:
                    orch = AuditOrchestrator(output_dir=str(self.base_dir), quiet=True)
                    snap_path = orch.run_audit()
                    AuditWebHandler.last_audit_message = f"Audit complete: {snap_path.name}"
                except Exception as e:
                    AuditWebHandler.last_audit_message = f"Audit failed: {str(e)}"
                finally:
                    AuditWebHandler.is_auditing = False

            threading.Thread(target=background_worker, daemon=True).start()
            self.send_json_response({"status": "started", "message": "Audit started in background"})
        else:
            self.send_json_response({"error": "Endpoint not found"}, status=404)

    @classmethod
    def render_dashboard(cls, snapshots: list, latest: dict = None) -> str:
        hostname = platform.node()
        latest_time = latest.get("timestamp", "Never") if latest else "No audits yet"
        
        rows = ""
        for s in snapshots:
            name = s["name"]
            ts = s["timestamp"]
            prof = s["profile"]
            rows += f"""
            <tr>
                <td><strong>{html.escape(name)}</strong></td>
                <td>{html.escape(ts)}</td>
                <td><code>{html.escape(prof)}</code></td>
                <td>
                    <a class="btn-sm" href="/api/snapshot/{name}/html" target="_blank">View HTML</a>
                    <a class="btn-sm" href="/api/snapshot/{name}/md" download>MD</a>
                    <a class="btn-sm" href="/api/snapshot/{name}" target="_blank">JSON</a>
                </td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Audit - {hostname}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --border: #475569;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{ font-size: 1.8rem; color: var(--accent); }}
        .btn {{
            background: var(--accent);
            color: #0f172a;
            border: none;
            padding: 0.75rem 1.5rem;
            font-weight: bold;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: var(--accent-hover); }}
        .btn-sm {{
            background: var(--bg-card);
            color: var(--text-primary);
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.85rem;
            margin-right: 0.3rem;
            border: 1px solid var(--border);
        }}
        .btn-sm:hover {{ background: var(--accent); color: #0f172a; }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h2 {{ font-size: 1.2rem; color: var(--accent); margin-bottom: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: var(--bg-card); color: var(--text-muted); }}
        code {{ background: var(--bg-card); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }}
        .online-dot {{
            display: inline-block;
            width: 10px;
            height: 10px;
            background: var(--success);
            border-radius: 50%;
            margin-right: 6px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>SERVER AUDIT DASHBOARD</h1>
                <div style="color: var(--text-muted); margin-top: 0.5rem;">
                    <span class="online-dot"></span><strong>{hostname}</strong> &bull; Version {__version__}
                </div>
            </div>
            <div>
                <button class="btn" onclick="runAudit()" id="runBtn">RUN NEW AUDIT</button>
            </div>
        </header>

        <div class="card">
            <h2>Last Recorded Audit</h2>
            <p style="font-size: 1.1rem; color: var(--text-primary);">
                Latest: <strong>{latest_time}</strong>
            </p>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.4rem;" id="auditStatus">
                Observational security status: Strict read-only mode active.
            </p>
        </div>

        <div class="card">
            <h2>Historical Snapshots ({len(snapshots)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Snapshot Identifier</th>
                        <th>Timestamp</th>
                        <th>Profile</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {rows or '<tr><td colspan="4" style="text-align:center;">No audits recorded yet. Click "RUN NEW AUDIT" to create the first snapshot.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function runAudit() {{
            const btn = document.getElementById('runBtn');
            const status = document.getElementById('auditStatus');
            btn.disabled = true;
            btn.innerText = "AUDIT IN PROGRESS...";
            status.innerText = "Collecting server state in background...";

            try {{
                const res = await fetch('/api/audit/run', {{ method: 'POST' }});
                const data = await res.json();
                if (res.ok) {{
                    pollStatus();
                }} else {{
                    alert(data.message || "Failed to start audit");
                    btn.disabled = false;
                    btn.innerText = "RUN NEW AUDIT";
                }}
            }} catch (err) {{
                alert("Error connecting to server audit backend");
                btn.disabled = false;
                btn.innerText = "RUN NEW AUDIT";
            }}
        }}

        function pollStatus() {{
            const interval = setInterval(async () => {{
                const res = await fetch('/api/status');
                const data = await res.json();
                if (!data.is_auditing) {{
                    clearInterval(interval);
                    document.getElementById('auditStatus').innerText = data.message;
                    setTimeout(() => {{ window.location.reload(); }}, 1000);
                }}
            }}, 2000);
        }}
    </script>
</body>
</html>
"""


def run_web_server(host: str = "127.0.0.1", port: int = 8080, base_dir: str = "audits") -> None:
    """Launches the self-hosted audit dashboard server."""
    AuditWebHandler.base_dir = Path(base_dir)
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, AuditWebHandler)
    print("======================================================================")
    print(f" Linux Server Audit Web Interface v{__version__}")
    print("======================================================================")
    print(f"Server running at: http://{host}:{port}/")
    print(f"Audit snapshots stored in: {base_dir}/")
    print("Press Ctrl+C to terminate.")
    print("----------------------------------------------------------------------")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb server stopped.")
    finally:
        httpd.server_close()
