"""
USB controllers, topology, and connected devices collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class UsbCollector(BaseCollector):
    manifest = CollectorManifest(
        name="usb",
        category="hardware",
        description="Collect USB controllers, buses, connected devices, vendor/product IDs, and drivers",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["lsusb", "lsusb -t"],
        outputs=["devices", "buses", "security_keys"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("lsusb"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="lsusb utility not found (usbutils not installed)",
            )

        data: Dict[str, Any] = {
            "devices": [],
            "security_keys": [],
        }

        res = executor.run(["lsusb"])
        if not res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                error=res.stderr,
                message="lsusb execution failed",
            )

        # Example line: Bus 001 Device 002: ID 8087:8000 Intel Corp. Integrated Rate Matching Hub
        usb_pattern = re.compile(r"^Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\s+(.*)$")
        for line in res.stdout.splitlines():
            line_str = line.strip()
            match = usb_pattern.match(line_str)
            if match:
                bus = match.group(1)
                dev_num = match.group(2)
                vid_pid = match.group(3)
                desc = match.group(4)

                dev_info = {
                    "bus": bus,
                    "device": dev_num,
                    "id": vid_pid,
                    "description": desc,
                    "is_hub": "hub" in desc.lower() or "root hub" in desc.lower(),
                }
                data["devices"].append(dev_info)

                lower_desc = desc.lower()
                if "yubikey" in lower_desc or "security key" in lower_desc or "fido" in lower_desc:
                    data["security_keys"].append(dev_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['devices'])} USB devices",
        )
