"""
Firewall state inspection (UFW, iptables, nftables, firewalld) collector for Linux Server Audit.
Strictly observational; never modifies firewall configuration.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class FirewallCollector(BaseCollector):
    manifest = CollectorManifest(
        name="firewall",
        category="network",
        description="Inspect UFW, iptables, nftables, and firewalld status, default policies, and rules",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ufw status verbose", "iptables-save", "nft list ruleset"],
        outputs=["ufw", "iptables", "nftables", "firewalld"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "active_frameworks": [],
            "ufw": {
                "installed": executor.which("ufw") is not None,
                "status": "inactive",
                "default_incoming": None,
                "default_outgoing": None,
                "rules": [],
            },
            "iptables": {
                "rules_count": 0,
                "has_docker_chains": False,
                "default_policies": {},
            },
            "nftables": {
                "installed": executor.which("nft") is not None,
                "tables_count": 0,
            },
            "firewalld": {
                "active": False,
            },
        }

        # 1. Inspect UFW
        if data["ufw"]["installed"]:
            ufw_res = executor.run(["ufw", "status", "verbose"], use_sudo=True)
            if ufw_res.success and ufw_res.stdout:
                if "Status: active" in ufw_res.stdout:
                    data["ufw"]["status"] = "active"
                    data["active_frameworks"].append("ufw")
                    for line in ufw_res.stdout.splitlines():
                        if line.startswith("Default:"):
                            parts = line.split(",")
                            for p in parts:
                                p_clean = p.strip()
                                if "incoming" in p_clean:
                                    data["ufw"]["default_incoming"] = p_clean.split()[0]
                                elif "outgoing" in p_clean:
                                    data["ufw"]["default_outgoing"] = p_clean.split()[0]
                        elif re.match(r"^\d+|^\w+", line) and ("ALLOW" in line or "DENY" in line or "LIMIT" in line):
                            data["ufw"]["rules"].append(line.strip())

        # 2. Inspect iptables-save
        if executor.which("iptables-save"):
            ipt_res = executor.run(["iptables-save"], use_sudo=True)
            if ipt_res.success and ipt_res.stdout:
                rules = [l for l in ipt_res.stdout.splitlines() if l.startswith("-A")]
                data["iptables"]["rules_count"] = len(rules)
                if "DOCKER" in ipt_res.stdout:
                    data["iptables"]["has_docker_chains"] = True
                for line in ipt_res.stdout.splitlines():
                    if line.startswith(":"):
                        # Policy line: :INPUT ACCEPT [123:456]
                        p_parts = line.split()
                        chain = p_parts[0].lstrip(":")
                        policy = p_parts[1] if len(p_parts) > 1 else ""
                        data["iptables"]["default_policies"][chain] = policy

                if data["iptables"]["rules_count"] > 0 and "ufw" not in data["active_frameworks"]:
                    data["active_frameworks"].append("iptables")

        # 3. Inspect nftables
        if data["nftables"]["installed"]:
            nft_res = executor.run(["nft", "list", "tables"], use_sudo=True)
            if nft_res.success and nft_res.stdout:
                tables = [l for l in nft_res.stdout.splitlines() if l.startswith("table")]
                data["nftables"]["tables_count"] = len(tables)
                if tables and "ufw" not in data["active_frameworks"] and "iptables" not in data["active_frameworks"]:
                    data["active_frameworks"].append("nftables")

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Firewall state inspected (Active: {', '.join(data['active_frameworks']) or 'none/open'})",
        )
