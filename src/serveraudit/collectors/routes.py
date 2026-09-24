"""
Routing tables, default gateway, and policy routing collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class RoutesCollector(BaseCollector):
    manifest = CollectorManifest(
        name="routes",
        category="network",
        description="Collect IPv4 and IPv6 routing tables, default gateways, and policy routing rules",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ip -j route show", "ip -j -6 route show", "ip rule show"],
        outputs=["ipv4_routes", "ipv6_routes", "default_gateway", "rules"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("ip"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="ip utility not found",
            )

        data: Dict[str, Any] = {
            "default_gateway": None,
            "default_gateway_interface": None,
            "ipv4_routes": [],
            "ipv6_routes": [],
            "rules": [],
        }

        # 1. IPv4 routes
        res_v4 = executor.run(["ip", "-j", "route", "show"])
        if res_v4.success and res_v4.stdout:
            try:
                routes_v4 = json.loads(res_v4.stdout)
                for r in routes_v4:
                    dst = r.get("dst")
                    gateway = r.get("gateway")
                    dev = r.get("dev")
                    protocol = r.get("protocol")
                    prefsrc = r.get("prefsrc")
                    metric = r.get("metric")

                    route_entry = {
                        "destination": dst,
                        "gateway": gateway,
                        "interface": dev,
                        "protocol": protocol,
                        "source": prefsrc,
                        "metric": metric,
                    }
                    data["ipv4_routes"].append(route_entry)

                    if dst == "default" and gateway and not data["default_gateway"]:
                        data["default_gateway"] = gateway
                        data["default_gateway_interface"] = dev
            except Exception:
                pass

        # 2. IPv6 routes
        res_v6 = executor.run(["ip", "-j", "-6", "route", "show"])
        if res_v6.success and res_v6.stdout:
            try:
                routes_v6 = json.loads(res_v6.stdout)
                for r in routes_v6:
                    data["ipv6_routes"].append({
                        "destination": r.get("dst"),
                        "gateway": r.get("gateway"),
                        "interface": r.get("dev"),
                        "metric": r.get("metric"),
                    })
            except Exception:
                pass

        # 3. Policy routing rules
        res_rules = executor.run(["ip", "rule", "show"])
        if res_rules.success and res_rules.stdout:
            for line in res_rules.stdout.splitlines():
                if line.strip():
                    data["rules"].append(line.strip())

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered default gateway ({data['default_gateway'] or 'none'}) and {len(data['ipv4_routes'])} IPv4 routes",
        )
