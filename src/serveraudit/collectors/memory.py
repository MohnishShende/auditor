"""
Memory, RAM, swap, DIMM inventory, HugePages, ECC, and PSI collector.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class MemoryCollector(BaseCollector):
    manifest = CollectorManifest(
        name="memory",
        category="hardware",
        description="Collect RAM metrics, swap utilization, DIMM hardware inventory, and memory pressure",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["free -b", "dmidecode -t memory"],
        outputs=["ram", "swap", "dimms", "hugepages", "pressure"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "ram": {
                "total_bytes": 0,
                "free_bytes": 0,
                "available_bytes": 0,
                "used_bytes": 0,
                "cached_bytes": 0,
                "buffers_bytes": 0,
                "percent_used": 0.0,
            },
            "swap": {
                "total_bytes": 0,
                "free_bytes": 0,
                "used_bytes": 0,
                "percent_used": 0.0,
                "swappiness": None,
            },
            "dimms": [],
            "total_slots": None,
            "used_slots": 0,
            "empty_slots": 0,
            "ecc_supported": False,
            "hugepages": {
                "total": 0,
                "free": 0,
                "size_kb": 0,
            },
            "pressure": {
                "some_avg10": None,
                "some_avg60": None,
                "some_avg300": None,
                "full_avg10": None,
                "full_avg60": None,
                "full_avg300": None,
            },
        }

        # 1. Parse /proc/meminfo
        meminfo = executor.read_file("/proc/meminfo")
        if meminfo:
            raw_mem: Dict[str, int] = {}
            for line in meminfo.splitlines():
                if ":" in line:
                    k, v = [x.strip() for x in line.split(":", 1)]
                    val_match = re.match(r"^(\d+)", v)
                    if val_match:
                        raw_mem[k] = int(val_match.group(1)) * 1024  # Meminfo reports in kB

            data["ram"]["total_bytes"] = raw_mem.get("MemTotal", 0)
            data["ram"]["free_bytes"] = raw_mem.get("MemFree", 0)
            data["ram"]["available_bytes"] = raw_mem.get("MemAvailable", raw_mem.get("MemFree", 0))
            data["ram"]["cached_bytes"] = raw_mem.get("Cached", 0)
            data["ram"]["buffers_bytes"] = raw_mem.get("Buffers", 0)

            total = data["ram"]["total_bytes"]
            avail = data["ram"]["available_bytes"]
            if total > 0:
                data["ram"]["used_bytes"] = total - avail
                data["ram"]["percent_used"] = round(((total - avail) / total) * 100, 2)

            data["swap"]["total_bytes"] = raw_mem.get("SwapTotal", 0)
            data["swap"]["free_bytes"] = raw_mem.get("SwapFree", 0)
            swap_total = data["swap"]["total_bytes"]
            swap_free = data["swap"]["free_bytes"]
            if swap_total > 0:
                data["swap"]["used_bytes"] = swap_total - swap_free
                data["swap"]["percent_used"] = round(((swap_total - swap_free) / swap_total) * 100, 2)

            data["hugepages"]["total"] = raw_mem.get("HugePages_Total", 0)
            data["hugepages"]["free"] = raw_mem.get("HugePages_Free", 0)
            data["hugepages"]["size_kb"] = raw_mem.get("Hugepagesize", 0) // 1024

        # 2. Swappiness
        swappiness = executor.read_file("/proc/sys/vm/swappiness")
        if swappiness and swappiness.strip().isdigit():
            data["swap"]["swappiness"] = int(swappiness.strip())

        # 3. Memory pressure from /proc/pressure/memory
        psi_mem = executor.read_file("/proc/pressure/memory")
        if psi_mem:
            for line in psi_mem.splitlines():
                if line.startswith("some"):
                    for part in line.split()[1:]:
                        if "=" in part:
                            pk, pv = part.split("=")
                            if pk in ("avg10", "avg60", "avg300"):
                                data["pressure"][f"some_{pk}"] = float(pv)
                elif line.startswith("full"):
                    for part in line.split()[1:]:
                        if "=" in part:
                            pk, pv = part.split("=")
                            if pk in ("avg10", "avg60", "avg300"):
                                data["pressure"][f"full_{pk}"] = float(pv)

        # 4. DIMM hardware inventory via dmidecode
        if executor.which("dmidecode") and executor.privileges.can_elevate:
            dmi_mem = executor.run(["dmidecode", "-t", "memory"], use_sudo=True)
            if dmi_mem.success:
                current_dimm: Dict[str, Any] = {}
                in_device = False
                dimms = []
                for line in dmi_mem.stdout.splitlines():
                    trimmed = line.strip()
                    if trimmed == "Memory Device":
                        if in_device and current_dimm.get("locator"):
                            dimms.append(current_dimm)
                        current_dimm = {
                            "locator": None,
                            "bank_locator": None,
                            "size": None,
                            "type": None,
                            "speed": None,
                            "manufacturer": None,
                            "part_number": None,
                            "serial_number": None,
                            "configured_speed": None,
                            "empty": True,
                        }
                        in_device = True
                    elif in_device and ":" in trimmed:
                        k, v = [x.strip() for x in trimmed.split(":", 1)]
                        if k == "Locator":
                            current_dimm["locator"] = v
                        elif k == "Bank Locator":
                            current_dimm["bank_locator"] = v
                        elif k == "Size":
                            current_dimm["size"] = v
                            if "No Module" not in v and v != "0 MB":
                                current_dimm["empty"] = False
                        elif k == "Type":
                            current_dimm["type"] = v
                        elif k == "Speed":
                            current_dimm["speed"] = v
                        elif k == "Manufacturer":
                            current_dimm["manufacturer"] = v
                        elif k == "Part Number":
                            current_dimm["part_number"] = v
                        elif k == "Serial Number":
                            current_dimm["serial_number"] = v
                        elif k == "Configured Memory Speed":
                            current_dimm["configured_speed"] = v

                if in_device and current_dimm.get("locator"):
                    dimms.append(current_dimm)

                if dimms:
                    data["dimms"] = dimms
                    data["total_slots"] = len(dimms)
                    data["empty_slots"] = sum(1 for d in dimms if d["empty"])
                    data["used_slots"] = data["total_slots"] - data["empty_slots"]

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Memory metrics and hardware inventory collected",
        )
