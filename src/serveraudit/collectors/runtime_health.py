"""
Runtime health, load averages, pressure stall information (PSI), and OOM events collector.
"""

from __future__ import annotations
import os
import re
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class RuntimeHealthCollector(BaseCollector):
    manifest = CollectorManifest(
        name="runtime_health",
        category="runtime",
        description="Collect system load averages, CPU/Memory/IO pressure stall metrics, and OOM killer events",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["dmesg -T"],
        outputs=["load_averages", "psi", "oom_events"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "load_averages": {
                "load1": 0.0,
                "load5": 0.0,
                "load15": 0.0,
                "running_processes": 0,
                "total_threads": 0,
            },
            "psi": {
                "cpu": {},
                "memory": {},
                "io": {},
            },
            "oom_events_count": 0,
            "recent_oom_kills": [],
        }

        # 1. /proc/loadavg
        loadavg = executor.read_file("/proc/loadavg")
        if loadavg:
            parts = loadavg.strip().split()
            if len(parts) >= 4:
                try:
                    data["load_averages"]["load1"] = float(parts[0])
                    data["load_averages"]["load5"] = float(parts[1])
                    data["load_averages"]["load15"] = float(parts[2])
                    proc_parts = parts[3].split("/")
                    if len(proc_parts) == 2:
                        data["load_averages"]["running_processes"] = int(proc_parts[0])
                        data["load_averages"]["total_threads"] = int(proc_parts[1])
                except (ValueError, IndexError):
                    pass

        # 2. Pressure Stall Information (/proc/pressure/*)
        for metric in ("cpu", "memory", "io"):
            content = executor.read_file(f"/proc/pressure/{metric}")
            if content:
                m_dict: Dict[str, Any] = {}
                for line in content.splitlines():
                    parts = line.split()
                    prefix = parts[0]
                    for item in parts[1:]:
                        if "=" in item:
                            k, v = item.split("=")
                            m_dict[f"{prefix}_{k}"] = float(v) if v.replace(".", "", 1).isdigit() else v
                data["psi"][metric] = m_dict

        # 3. Check for OOM killer events in dmesg
        dmesg_res = executor.run(["dmesg", "--ctime"], use_sudo=True)
        if dmesg_res.success and dmesg_res.stdout:
            for line in dmesg_res.stdout.splitlines():
                if "invoked oom-killer" in line.lower() or "killed process" in line.lower() and "out of memory" in line.lower():
                    data["oom_events_count"] += 1
                    data["recent_oom_kills"].append(line.strip())

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Runtime health recorded (Load: {data['load_averages']['load1']}, {data['load_averages']['load5']}, {data['load_averages']['load15']})",
        )
