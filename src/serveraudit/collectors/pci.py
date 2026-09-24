"""
PCI and internal hardware devices collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class PciCollector(BaseCollector):
    manifest = CollectorManifest(
        name="pci",
        category="hardware",
        description="Collect PCI inventory, controllers, GPUs, NICs, drivers, and IOMMU groups",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["lspci -nnk", "lspci -mm"],
        outputs=["devices", "gpus", "nics", "storage_controllers"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("lspci"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="lspci utility not found (pciutils not installed)",
            )

        data: Dict[str, Any] = {
            "devices": [],
            "gpus": [],
            "nics": [],
            "storage_controllers": [],
        }

        res = executor.run(["lspci", "-nnk"])
        if not res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                error=res.stderr,
                message="lspci execution failed",
            )

        current_dev: Dict[str, Any] = {}
        for block in res.stdout.strip().split("\n\n"):
            lines = block.strip().splitlines()
            if not lines:
                continue

            first_line = lines[0]
            # Format: 00:02.0 VGA compatible controller [0300]: Intel Corporation ... [8086:9bc8] (rev 03)
            slot_match = re.match(r"^([0-9a-fA-F:.]+)\s+([^\[]+)(?:\[([0-9a-fA-F]+)\])?:\s+(.*)$", first_line)
            slot = slot_match.group(1) if slot_match else first_line.split()[0]
            class_name = slot_match.group(2).strip() if slot_match else ""
            desc = slot_match.group(4).strip() if slot_match else first_line

            driver = None
            modules = []

            for line in lines[1:]:
                line_str = line.strip()
                if "Kernel driver in use:" in line_str:
                    driver = line_str.split(":", 1)[1].strip()
                elif "Kernel modules:" in line_str:
                    modules = line_str.split(":", 1)[1].strip().split(", ")

            dev_info = {
                "slot": slot,
                "class": class_name,
                "description": desc,
                "driver": driver,
                "modules": modules,
            }
            data["devices"].append(dev_info)

            # Categorize
            lower_desc = (class_name + " " + desc).lower()
            if "vga" in lower_desc or "3d" in lower_desc or "display" in lower_desc:
                data["gpus"].append(dev_info)
            elif "ethernet" in lower_desc or "network" in lower_desc or "wireless" in lower_desc:
                data["nics"].append(dev_info)
            elif "sata" in lower_desc or "nvme" in lower_desc or "raid" in lower_desc or "storage" in lower_desc:
                data["storage_controllers"].append(dev_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['devices'])} PCI devices",
        )
