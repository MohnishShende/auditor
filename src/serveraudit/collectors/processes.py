"""
Process tree, resource consumers, and runtime process collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class ProcessesCollector(BaseCollector):
    manifest = CollectorManifest(
        name="processes",
        category="runtime",
        description="Collect process count, top CPU and memory consumers, and zombie processes",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["ps aux --sort=-%cpu", "ps aux --sort=-%mem"],
        outputs=["total_processes", "top_cpu_processes", "top_memory_processes", "zombies"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "total_processes": 0,
            "zombies": [],
            "top_cpu_processes": [],
            "top_memory_processes": [],
        }

        # 1. ps aux
        ps_res = executor.run(["ps", "aux"])
        if not ps_res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                error=ps_res.stderr,
                message="ps command failed",
            )

        all_procs: List[Dict[str, Any]] = []
        for line in ps_res.stdout.splitlines()[1:]:
            parts = line.split(maxsplit=10)
            if len(parts) >= 11:
                user = parts[0]
                pid = int(parts[1]) if parts[1].isdigit() else -1
                cpu = float(parts[2]) if parts[2].replace(".", "", 1).isdigit() else 0.0
                mem = float(parts[3]) if parts[3].replace(".", "", 1).isdigit() else 0.0
                vsz = int(parts[4]) if parts[4].isdigit() else 0
                rss = int(parts[5]) if parts[5].isdigit() else 0
                stat = parts[7]
                cmd = parts[10]

                # Basic sanitization of obvious inline credentials
                clean_cmd = re.sub(r"""(?i)(password|token|secret|key)=\S+""", r"\1=[REDACTED]", cmd)

                proc_info = {
                    "user": user,
                    "pid": pid,
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "rss_kb": rss,
                    "stat": stat,
                    "command": clean_cmd,
                }
                all_procs.append(proc_info)

                if "Z" in stat:
                    data["zombies"].append(proc_info)

        data["total_processes"] = len(all_procs)

        # Sort top 10 CPU
        data["top_cpu_processes"] = sorted(all_procs, key=lambda p: p["cpu_percent"], reverse=True)[:10]

        # Sort top 10 Memory
        data["top_memory_processes"] = sorted(all_procs, key=lambda p: p["memory_percent"], reverse=True)[:10]

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {data['total_processes']} running processes ({len(data['zombies'])} zombies)",
        )
