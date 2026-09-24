"""
DNS resolver configuration, systemd-resolved, and hosts collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class DnsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="dns",
        category="network",
        description="Inspect /etc/resolv.conf, systemd-resolved status, search domains, and /etc/hosts entries",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["resolvectl status", "systemd-resolve --status"],
        outputs=["nameservers", "search_domains", "resolved_active", "hosts_entries"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "nameservers": [],
            "search_domains": [],
            "options": [],
            "resolv_conf_symlink": None,
            "resolved_active": False,
            "hosts_entries": [],
        }

        # 1. Parse /etc/resolv.conf
        resolv_path = Path("/etc/resolv.conf")
        if resolv_path.is_symlink():
            try:
                data["resolv_conf_symlink"] = str(resolv_path.resolve())
            except Exception:
                pass

        resolv_content = executor.read_file("/etc/resolv.conf")
        if resolv_content:
            for line in resolv_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if parts[0] == "nameserver" and len(parts) > 1:
                    data["nameservers"].append(parts[1])
                elif parts[0] in ("search", "domain") and len(parts) > 1:
                    data["search_domains"].extend(parts[1:])
                elif parts[0] == "options" and len(parts) > 1:
                    data["options"].extend(parts[1:])

        # 2. Check systemd-resolved / resolvectl
        if executor.which("resolvectl"):
            resctl = executor.run(["resolvectl", "status"])
            if resctl.success:
                data["resolved_active"] = True

        # 3. Parse /etc/hosts
        hosts_content = executor.read_file("/etc/hosts")
        if hosts_content:
            for line in hosts_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostnames = parts[1:]
                    data["hosts_entries"].append({
                        "ip": ip,
                        "hostnames": hostnames,
                    })

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['nameservers'])} DNS nameservers and {len(data['hosts_entries'])} static hosts entries",
        )
