"""
systemd service units, failed units, timers, sockets, and boot performance collector.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SystemdCollector(BaseCollector):
    manifest = CollectorManifest(
        name="systemd",
        category="runtime",
        description="Collect systemd units, failed services, enabled/disabled units, timers, and boot duration",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["systemctl list-units --all --no-pager", "systemctl --failed --no-pager", "systemd-analyze"],
        outputs=["failed_units", "active_services", "timers", "boot_time"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("systemctl"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="systemctl / systemd not active on host",
            )

        data: Dict[str, Any] = {
            "version": None,
            "failed_units": [],
            "running_services": [],
            "enabled_services_count": 0,
            "timers": [],
            "boot_time": {
                "kernel_seconds": None,
                "userspace_seconds": None,
                "total_seconds": None,
            },
        }

        # 1. Version
        ver_res = executor.run(["systemctl", "--version"])
        if ver_res.success and ver_res.stdout:
            first_line = ver_res.stdout.splitlines()[0]
            data["version"] = first_line

        # 2. Failed units
        failed_res = executor.run(["systemctl", "--failed", "--no-legend", "--no-pager"])
        if failed_res.success and failed_res.stdout:
            for line in failed_res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4:
                    unit_name = parts[0]
                    load = parts[1]
                    active = parts[2]
                    sub = parts[3]
                    desc = " ".join(parts[4:]) if len(parts) > 4 else ""
                    data["failed_units"].append({
                        "unit": unit_name,
                        "load": load,
                        "active": active,
                        "sub": sub,
                        "description": desc,
                    })

        # 3. Active service units
        services_res = executor.run([
            "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"
        ])
        if services_res.success and services_res.stdout:
            for line in services_res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 1:
                    data["running_services"].append(parts[0])

        # 4. Systemd timers
        timers_res = executor.run(["systemctl", "list-timers", "--no-legend", "--no-pager"])
        if timers_res.success and timers_res.stdout:
            for line in timers_res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 6:
                    unit = parts[-2] if len(parts) >= 2 else parts[-1]
                    activates = parts[-1]
                    data["timers"].append({
                        "unit": unit,
                        "activates": activates,
                    })

        # 5. Boot performance via systemd-analyze
        if executor.which("systemd-analyze"):
            analyze_res = executor.run(["systemd-analyze", "time"])
            if analyze_res.success and analyze_res.stdout:
                # Startup finished in 2.123s (kernel) + 4.567s (userspace) = 6.690s
                m = re.search(r"in\s+([0-9.]+s)\s+\(kernel\)\s+\+\s+([0-9.]+s)\s+\(userspace\)\s+=\s+([0-9.]+s)", analyze_res.stdout)
                if m:
                    data["boot_time"]["kernel_seconds"] = m.group(1)
                    data["boot_time"]["userspace_seconds"] = m.group(2)
                    data["boot_time"]["total_seconds"] = m.group(3)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['running_services'])} running services ({len(data['failed_units'])} failed units)",
        )
