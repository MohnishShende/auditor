"""
System log error summaries, kernel alerts, and log storage usage collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class LogsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="logs",
        category="runtime",
        description="Collect summarized journalctl errors, dmesg hardware/driver alerts, and log disk utilization",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["journalctl -p 3 -b --no-pager -n 50", "journalctl --disk-usage"],
        outputs=["error_count", "recent_critical_logs", "log_disk_usage"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "journal_disk_usage": None,
            "boot_errors_count": 0,
            "recent_errors": [],
            "kernel_alerts": [],
        }

        # 1. journalctl --disk-usage
        if executor.which("journalctl"):
            usage_res = executor.run(["journalctl", "--disk-usage"], use_sudo=True)
            if usage_res.success and usage_res.stdout:
                data["journal_disk_usage"] = usage_res.stdout.strip()

            # 2. Query priority 3 (errors) and above for current boot (-b)
            err_res = executor.run(["journalctl", "-p", "3", "-b", "--no-pager", "-n", "30"], use_sudo=True)
            if err_res.success and err_res.stdout:
                lines = [l.strip() for l in err_res.stdout.splitlines() if l.strip() and not l.startswith("--")]
                data["boot_errors_count"] = len(lines)
                for line in lines[:15]:  # Capture top 15 recent
                    data["recent_errors"].append(line)

        # 3. dmesg error and warning summary
        dmesg_res = executor.run(["dmesg", "--level=err,crit,alert,emerg"], use_sudo=True)
        if dmesg_res.success and dmesg_res.stdout:
            for line in dmesg_res.stdout.splitlines()[:15]:
                if line.strip():
                    data["kernel_alerts"].append(line.strip())

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Logged {data['boot_errors_count']} system boot errors and {len(data['kernel_alerts'])} kernel alerts",
        )
