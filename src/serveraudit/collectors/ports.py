"""
Listening TCP and UDP ports and service binding collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class PortsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="ports",
        category="network",
        description="Collect listening TCP and UDP ports, bound addresses, owning processes, and service exposure",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ss -tulpn", "netstat -tulpn"],
        outputs=["listening_ports", "loopback_only", "exposed_lan", "exposed_public"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "listening_ports": [],
            "loopback_only": [],
            "exposed_all": [],
            "exposed_specific": [],
        }

        # 1. Prefer ss -tulpn (iproute2)
        ss_res = executor.run(["ss", "-tulpn"], use_sudo=True)
        if ss_res.success and ss_res.stdout:
            for line in ss_res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue

                proto = parts[0].lower()
                state = parts[1].upper() if len(parts) > 1 else ""

                # Only examine LISTEN or UNCONN (for UDP)
                if proto.startswith("tcp") and state != "LISTEN":
                    continue

                local_addr_raw = parts[4] if len(parts) > 4 else ""
                process_info = parts[6] if len(parts) > 6 else (parts[5] if len(parts) > 5 else "")

                # Parse address and port
                # Examples: 127.0.0.1:8080, *:22, [::]:80, :::80, 0.0.0.0:443
                ip = ""
                port = 0

                if ":" in local_addr_raw:
                    last_colon = local_addr_raw.rfind(":")
                    ip = local_addr_raw[:last_colon].strip("[]")
                    port_str = local_addr_raw[last_colon + 1:]
                    port = int(port_str) if port_str.isdigit() else 0
                else:
                    continue

                # Process attribution: users:(("sshd",pid=1234,fd=3))
                proc_name = None
                pid = None
                proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', process_info)
                if proc_match:
                    proc_name = proc_match.group(1)
                    pid = int(proc_match.group(2))

                # Exposure classification
                exposure = "specific"
                if ip in ("127.0.0.1", "::1", "localhost"):
                    exposure = "loopback"
                elif ip in ("0.0.0.0", "*", "::", ""):
                    exposure = "all_interfaces"
                elif ip.startswith(("10.", "172.", "192.168.")):
                    exposure = "lan_only"

                entry = {
                    "protocol": proto,
                    "address": ip,
                    "port": port,
                    "exposure": exposure,
                    "process": proc_name,
                    "pid": pid,
                    "raw_process": process_info,
                }

                data["listening_ports"].append(entry)
                if exposure == "loopback":
                    data["loopback_only"].append(entry)
                elif exposure == "all_interfaces":
                    data["exposed_all"].append(entry)
                else:
                    data["exposed_specific"].append(entry)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['listening_ports'])} listening ports ({len(data['exposed_all'])} bound to all interfaces)",
        )
