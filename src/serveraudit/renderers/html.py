"""
Standalone interactive HTML report renderer for Linux Server Audit.
"""

from __future__ import annotations
import html
import json
from typing import Any, Dict
from ..core.normalizer import Normalizer


class HtmlRenderer:
    """Renders canonical audit data into a single-file, self-contained HTML dashboard."""

    @classmethod
    def render(cls, data: Dict[str, Any]) -> str:
        meta = data.get("metadata", {})
        sys = data.get("system", {})
        hw = data.get("hardware", {})
        cpu = data.get("cpu", {})
        mem = data.get("memory", {})
        storage = data.get("storage", {})
        smart = data.get("smart", {})
        net = data.get("network", {})
        ssh = data.get("ssh", {})
        docker = data.get("docker", {})
        caddy = data.get("caddy", {})
        apps = data.get("applications", {})
        findings = data.get("analysis", {}).get("health", [])
        exposure = data.get("analysis", {}).get("exposure", [])
        storage_chains = data.get("topology", {}).get("storage_chains", [])

        hostname = html.escape(str(meta.get("hostname", "unknown")))
        os_name = html.escape(str(sys.get("os", {}).get("pretty_name", "Linux")))
        kernel = html.escape(str(sys.get("kernel", {}).get("release", "unknown")))
        timestamp = html.escape(str(meta.get("timestamp", "unknown")))

        # Build findings table HTML
        findings_rows = ""
        if findings:
            for f in findings:
                sev = f.get("severity", "NOTICE")
                badge_class = "badge-danger" if sev == "CRITICAL" else ("badge-warning" if sev == "WARNING" else "badge-info")
                findings_rows += f"""
                <tr>
                    <td><span class="badge {badge_class}">{html.escape(sev)}</span></td>
                    <td>{html.escape(f.get('subsystem', ''))}</td>
                    <td><strong>{html.escape(f.get('title', ''))}</strong></td>
                    <td>{html.escape(f.get('details', ''))}</td>
                </tr>
                """
        else:
            findings_rows = "<tr><td colspan='4' class='text-success'>✓ No critical health anomalies or hardware warnings detected.</td></tr>"

        # Build disks table HTML
        disk_rows = ""
        smart_map = {d.get("device"): d for d in smart.get("devices", [])}
        for d in storage.get("disks", []):
            d_path = d.get("path", "")
            sm = smart_map.get(d_path, {})
            s_stat = sm.get("status", "PASSED")
            s_class = "badge-success" if s_stat == "PASSED" else "badge-danger"
            disk_rows += f"""
            <tr>
                <td><code>{html.escape(d_path)}</code></td>
                <td>{html.escape(d.get('media', '').upper())}</td>
                <td>{html.escape(d.get('model') or 'Unknown')}</td>
                <td>{html.escape(d.get('size_formatted', ''))}</td>
                <td><span class="badge {s_class}">{html.escape(s_stat)}</span></td>
                <td>{sm.get('temperature_c', 'N/A')}°C</td>
                <td>{sm.get('reallocated_sectors', 0)}</td>
            </tr>
            """

        # Build containers table HTML
        container_rows = ""
        for c in docker.get("containers", []):
            st = c.get("state", "")
            st_class = "badge-success" if st == "running" else "badge-secondary"
            ports_str = ", ".join([f"{p.get('host_port')}->{p.get('container_port')}" for p in c.get("ports", []) if p.get("host_port")]) or "-"
            container_rows += f"""
            <tr>
                <td><strong>{html.escape(c.get('name', ''))}</strong></td>
                <td><code>{html.escape(c.get('image', ''))}</code></td>
                <td><span class="badge {st_class}">{html.escape(st)}</span></td>
                <td>{html.escape(ports_str)}</td>
                <td>{html.escape(c.get('compose_project') or '-')}</td>
            </tr>
            """

        # Build HTML page
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
            --warning: #f59e0b;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        h1 {{ font-size: 1.8rem; color: var(--accent); }}
        .header-meta {{ color: var(--text-muted); font-size: 0.95rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
        }}
        .card-title {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; margin-bottom: 0.5rem; }}
        .card-value {{ font-size: 1.4rem; font-weight: bold; color: var(--text-primary); }}
        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        h2 {{ font-size: 1.3rem; margin-bottom: 1rem; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.95rem; }}
        th {{ background: var(--bg-card); color: var(--text-muted); font-weight: 600; }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        code {{ background: var(--bg-card); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-info {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }}
        .badge-secondary {{ background: var(--bg-card); color: var(--text-muted); }}
        .text-success {{ color: var(--success); }}
        pre {{ background: var(--bg-primary); padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.9rem; border: 1px solid var(--border); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Server Audit Report</h1>
                <div class="header-meta">
                    <strong>{hostname}</strong> &bull; {os_name} &bull; Kernel {kernel}
                </div>
            </div>
            <div class="header-meta" style="text-align: right;">
                <div>Audit: <strong>{timestamp}</strong></div>
                <div>Profile: <code>{meta.get('profile', 'private')}</code></div>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-title">Memory (RAM)</div>
                <div class="card-value">{Normalizer.format_bytes(mem.get('ram', {}).get('total_bytes'))}</div>
                <div class="header-meta">{mem.get('ram', {}).get('percent_used', 0)}% utilized</div>
            </div>
            <div class="card">
                <div class="card-title">CPU Processor</div>
                <div class="card-value">{cpu.get('physical_cores', 1)} Cores</div>
                <div class="header-meta">{cpu.get('logical_cpus', 1)} Threads ({cpu.get('model_name') or 'CPU'})</div>
            </div>
            <div class="card">
                <div class="card-title">Storage & Health</div>
                <div class="card-value">{len(storage.get('disks', []))} Disks</div>
                <div class="header-meta">SMART {'Passed' if smart.get('overall_health_passed', True) else 'Degraded'}</div>
            </div>
            <div class="card">
                <div class="card-title">Containers</div>
                <div class="card-value">{docker.get('engine', {}).get('containers_running', 0)} / {docker.get('engine', {}).get('containers_total', 0)}</div>
                <div class="header-meta">Running Containers</div>
            </div>
        </div>

        <div class="section">
            <h2>Findings & Health Assessment</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Subsystem</th>
                        <th>Finding</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Physical Storage & SMART Health</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device</th>
                        <th>Type</th>
                        <th>Model</th>
                        <th>Capacity</th>
                        <th>SMART Status</th>
                        <th>Temp</th>
                        <th>Reallocated</th>
                    </tr>
                </thead>
                <tbody>
                    {disk_rows or '<tr><td colspan="7">No physical disks discovered.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Docker Containers</h2>
            <table>
                <thead>
                    <tr>
                        <th>Container</th>
                        <th>Image</th>
                        <th>State</th>
                        <th>Port Mappings</th>
                        <th>Compose Project</th>
                    </tr>
                </thead>
                <tbody>
                    {container_rows or '<tr><td colspan="5">No Docker containers running.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Provenance & Integrity</h2>
            <p class="header-meta">
                Generated locally by <code>serveraudit v{meta.get('tool_version', '0.1.0')}</code> with zero network access and zero system modification.
            </p>
        </div>
    </div>
</body>
</html>
"""
