"""
Software RAID (/proc/mdstat, mdadm) collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class RaidCollector(BaseCollector):
    manifest = CollectorManifest(
        name="raid",
        category="storage",
        description="Inspect Linux software RAID arrays, member devices, sync status, and degraded state",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["cat /proc/mdstat", "mdadm --detail --scan"],
        outputs=["arrays", "degraded_arrays"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        mdstat = executor.read_file("/proc/mdstat")
        if not mdstat or "Personalities" not in mdstat:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="No Linux Software RAID active (/proc/mdstat empty or absent)",
            )

        data: Dict[str, Any] = {
            "arrays": [],
            "degraded_arrays": [],
            "personalities": [],
        }

        # Parse Personalities : [raid1] [raid6] [raid5] [raid4] ...
        pers_match = re.search(r"Personalities\s*:\s*(.*)", mdstat)
        if pers_match:
            data["personalities"] = re.findall(r"\[(.*?)\]", pers_match.group(1))

        # Parse arrays: md0 : active raid1 sdb1[1] sda1[0]
        array_blocks = re.findall(r"^(md\d+|md_\w+)\s*:\s*(.*?)(?=\n\S|\n*$)", mdstat, re.MULTILINE | re.DOTALL)
        for name, block in array_blocks:
            lines = block.strip().splitlines()
            first_line = lines[0]
            parts = first_line.split()
            state = parts[0] if parts else "unknown"
            level = parts[1] if len(parts) > 1 else "unknown"
            devices = parts[2:] if len(parts) > 2 else []

            is_degraded = False
            # Check for degraded markers like [U_] or [2/1]
            status_line = " ".join(lines[1:])
            if "_" in status_line:
                is_degraded = True

            array_info = {
                "name": name,
                "device": f"/dev/{name}",
                "state": state,
                "level": level,
                "members": devices,
                "is_degraded": is_degraded,
                "raw_status": status_line.strip(),
            }
            data["arrays"].append(array_info)
            if is_degraded:
                data["degraded_arrays"].append(array_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['arrays'])} RAID arrays ({len(data['degraded_arrays'])} degraded)",
        )
