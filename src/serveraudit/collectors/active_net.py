"""
Active network connection state and interface statistics collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class ActiveNetCollector(BaseCollector):
    manifest = CollectorManifest(
        name="active_net",
        category="network",
        description="Summarize active TCP socket connection states, traffic statistics, and interface errors/drops",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ss -s"],
        outputs=["connection_summary", "interface_stats"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "connection_summary": {
                "total_sockets": 0,
                "tcp_established": 0,
                "tcp_time_wait": 0,
                "tcp_close_wait": 0,
                "tcp_syn_recv": 0,
                "tcp_listen": 0,
            },
            "interface_stats": {},
        }

        # 1. ss -s summary
        if executor.which("ss"):
            ss_s = executor.run(["ss", "-s"])
            if ss_s.success and ss_s.stdout:
                for line in ss_s.stdout.splitlines():
                    if "TCP:" in line:
                        estab_m = re.search(r"estab\s+(\d+)", line)
                        if estab_m:
                            data["connection_summary"]["tcp_established"] = int(estab_m.group(1))
                        tw_m = re.search(r"timewait\s+(\d+)", line)
                        if tw_m:
                            data["connection_summary"]["tcp_time_wait"] = int(tw_m.group(1))
                        listen_m = re.search(r"listen\s+(\d+)", line)
                        if listen_m:
                            data["connection_summary"]["tcp_listen"] = int(listen_m.group(1))

        # 2. Interface traffic & drop/error stats from /proc/net/dev
        dev_content = executor.read_file("/proc/net/dev")
        if dev_content:
            lines = dev_content.splitlines()
            for line in lines[2:]:
                if ":" in line:
                    iface, stats = line.split(":", 1)
                    iface = iface.strip()
                    cols = stats.split()
                    if len(cols) >= 16:
                        data["interface_stats"][iface] = {
                            "rx_bytes": int(cols[0]),
                            "rx_packets": int(cols[1]),
                            "rx_errors": int(cols[2]),
                            "rx_dropped": int(cols[3]),
                            "tx_bytes": int(cols[8]),
                            "tx_packets": int(cols[9]),
                            "tx_errors": int(cols[10]),
                            "tx_dropped": int(cols[11]),
                        }

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Active network state and interface counters summarized",
        )
