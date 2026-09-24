"""
Caddy web server, Caddyfile sites, reverse proxy routing, and TLS config collector.
Strictly NEVER exports private keys.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class CaddyCollector(BaseCollector):
    manifest = CollectorManifest(
        name="caddy",
        category="services",
        description="Inspect Caddy reverse proxy sites, upstreams, routes, and TLS configuration",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["caddy version", "caddy adapt --config /etc/caddy/Caddyfile"],
        outputs=["version", "sites", "reverse_proxies", "caddyfile_path"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "installed": executor.which("caddy") is not None,
            "version": None,
            "caddyfile_path": None,
            "sites": [],
            "reverse_proxies": [],
        }

        # 1. Version
        if data["installed"]:
            ver_res = executor.run(["caddy", "version"])
            if ver_res.success and ver_res.stdout:
                data["version"] = ver_res.stdout.strip()

        # 2. Locate Caddyfile
        candidate_paths = [
            "/etc/caddy/Caddyfile",
            "/etc/caddy/caddy.conf",
            "/etc/Caddyfile",
            "/srv/caddy/Caddyfile",
            "/opt/caddy/Caddyfile",
        ]
        caddyfile_content = None
        for cp in candidate_paths:
            content = executor.read_file(cp)
            if content:
                data["caddyfile_path"] = cp
                caddyfile_content = content
                break

        # 3. Parse Caddyfile structure
        if caddyfile_content:
            # Simple regex parser for Caddyfile site blocks
            current_site: Dict[str, Any] = {}
            for line in caddyfile_content.splitlines():
                line_clean = line.strip()
                if not line_clean or line_clean.startswith("#"):
                    continue

                # Site block start (e.g. "paperless.local:443 {", "example.com {")
                if "{" in line_clean and not line_clean.startswith(("reverse_proxy", "handle", "route")):
                    site_name = line_clean.split("{")[0].strip()
                    if site_name:
                        current_site = {
                            "hostname": site_name,
                            "reverse_proxies": [],
                            "tls_mode": "auto",
                            "has_file_server": False,
                        }
                        data["sites"].append(current_site)

                elif "reverse_proxy" in line_clean and current_site:
                    # e.g. reverse_proxy localhost:8000 or reverse_proxy 127.0.0.1:8096
                    parts = line_clean.split()
                    if len(parts) >= 2:
                        upstream = parts[1]
                        current_site["reverse_proxies"].append(upstream)
                        data["reverse_proxies"].append({
                            "site": current_site["hostname"],
                            "upstream": upstream,
                        })

                elif "tls" in line_clean and current_site:
                    tls_parts = line_clean.split()
                    if len(tls_parts) > 1:
                        current_site["tls_mode"] = tls_parts[1]

                elif "file_server" in line_clean and current_site:
                    current_site["has_file_server"] = True

        if not data["installed"] and not data["caddyfile_path"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="Caddy web server not detected on host",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['sites'])} Caddy sites with {len(data['reverse_proxies'])} reverse proxy routes",
        )
