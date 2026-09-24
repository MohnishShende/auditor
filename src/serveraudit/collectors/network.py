"""
Network hardware, interfaces, MAC addresses, and addressing collector for Linux Server Audit.
"""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class NetworkCollector(BaseCollector):
    manifest = CollectorManifest(
        name="network",
        category="network",
        description="Collect network interfaces, MAC addresses, link state, MTU, IPv4/IPv6 addresses, and bridges",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ip -j link", "ip -j addr", "ip link", "ip addr"],
        outputs=["interfaces", "physical_interfaces", "virtual_interfaces"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("ip"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="ip utility (iproute2) not found",
            )

        data: Dict[str, Any] = {
            "interfaces": [],
            "physical_interfaces": [],
            "virtual_interfaces": [],
        }

        # 1. Try JSON output: ip -j addr
        addr_res = executor.run(["ip", "-j", "addr"])
        if addr_res.success and addr_res.stdout:
            try:
                addr_json = json.loads(addr_res.stdout)
                for iface in addr_json:
                    ifname = iface.get("ifname")
                    mac = iface.get("address")
                    operstate = iface.get("operstate", "UNKNOWN").upper()
                    mtu = iface.get("mtu")
                    link_type = iface.get("link_type", "ether")
                    flags = iface.get("flags", [])

                    ipv4_addrs = []
                    ipv6_addrs = []

                    for addr_info in iface.get("addr_info", []):
                        family = addr_info.get("family")
                        local = addr_info.get("local")
                        prefixlen = addr_info.get("prefixlen")
                        scope = addr_info.get("scope")
                        if local:
                            entry = {
                                "address": local,
                                "prefixlen": prefixlen,
                                "cidr": f"{local}/{prefixlen}",
                                "scope": scope,
                            }
                            if family == "inet":
                                ipv4_addrs.append(entry)
                            elif family == "inet6":
                                ipv6_addrs.append(entry)

                    is_virtual = (
                        ifname.startswith(("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "tailscale", "dummy"))
                        or link_type in ("loopback", "none")
                    )

                    info = {
                        "name": ifname,
                        "mac": mac,
                        "state": operstate,
                        "mtu": mtu,
                        "link_type": link_type,
                        "is_virtual": is_virtual,
                        "is_up": "UP" in flags or operstate == "UP",
                        "ipv4": ipv4_addrs,
                        "ipv6": ipv6_addrs,
                        "flags": flags,
                    }

                    data["interfaces"].append(info)
                    if is_virtual:
                        data["virtual_interfaces"].append(info)
                    else:
                        data["physical_interfaces"].append(info)

                return CollectorResult(
                    collector=self.name,
                    status=CollectorStatus.SUCCESS,
                    data=data,
                    message=f"Discovered {len(data['interfaces'])} network interfaces ({len(data['physical_interfaces'])} physical)",
                )
            except Exception:
                pass

        # Fallback to plain text ip addr parsing
        text_res = executor.run(["ip", "addr"])
        if text_res.success:
            current_iface: Dict[str, Any] = {}
            for line in text_res.stdout.splitlines():
                if line and not line.startswith(" "):
                    if current_iface.get("name"):
                        data["interfaces"].append(current_iface)
                    parts = line.split(":")
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        current_iface = {
                            "name": name,
                            "mac": None,
                            "state": "UP" if "UP" in line else "DOWN",
                            "mtu": None,
                            "is_virtual": name.startswith(("lo", "docker", "br-", "veth", "virbr")),
                            "ipv4": [],
                            "ipv6": [],
                        }
                elif line.strip().startswith("link/ether"):
                    mac_parts = line.strip().split()
                    if len(mac_parts) >= 2:
                        current_iface["mac"] = mac_parts[1]
                elif line.strip().startswith("inet "):
                    ip_parts = line.strip().split()
                    if len(ip_parts) >= 2:
                        current_iface["ipv4"].append({"cidr": ip_parts[1]})
                elif line.strip().startswith("inet6 "):
                    ip_parts = line.strip().split()
                    if len(ip_parts) >= 2:
                        current_iface["ipv6"].append({"cidr": ip_parts[1]})

            if current_iface.get("name"):
                data["interfaces"].append(current_iface)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['interfaces'])} network interfaces",
        )
