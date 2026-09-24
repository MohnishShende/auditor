"""
Power management, ACPI power supply, and UPS monitoring collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class PowerCollector(BaseCollector):
    manifest = CollectorManifest(
        name="power",
        category="hardware",
        description="Inspect system power state, ACPI supplies, batteries, and UPS monitoring",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["upsc <ups>", "powerprofilesctl get"],
        outputs=["power_supplies", "ups_devices", "power_profile"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "power_supplies": [],
            "ups_devices": [],
            "power_profile": None,
        }

        # 1. Sysfs power supply inspection
        ps_dir = Path("/sys/class/power_supply")
        if ps_dir.exists():
            for ps in ps_dir.iterdir():
                ps_type = (executor.read_file(ps / "type") or "").strip()
                ps_online = (executor.read_file(ps / "online") or "").strip()
                ps_status = (executor.read_file(ps / "status") or "").strip()
                data["power_supplies"].append({
                    "name": ps.name,
                    "type": ps_type,
                    "online": ps_online == "1" if ps_online else None,
                    "status": ps_status or None,
                })

        # 2. Power profiles daemon
        if executor.which("powerprofilesctl"):
            prof_res = executor.run(["powerprofilesctl", "get"])
            if prof_res.success and prof_res.stdout:
                data["power_profile"] = prof_res.stdout.strip()

        # 3. Network UPS Tools (NUT) upsc
        if executor.which("upsc"):
            ups_res = executor.run(["upsc", "-l"])
            if ups_res.success and ups_res.stdout:
                for ups_name in ups_res.stdout.splitlines():
                    if ups_name.strip():
                        data["ups_devices"].append(ups_name.strip())

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Power management and supply metrics collected",
        )
