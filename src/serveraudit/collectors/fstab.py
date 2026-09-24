"""
/etc/fstab configuration and static filesystem table collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class FstabCollector(BaseCollector):
    manifest = CollectorManifest(
        name="fstab",
        category="storage",
        description="Parse and audit /etc/fstab entries, mount options, dump/pass numbers, and check for stale targets",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=[],
        outputs=["entries", "warnings"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        content = executor.read_file("/etc/fstab")
        if not content:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="/etc/fstab not found or empty",
            )

        data: Dict[str, Any] = {
            "entries": [],
            "warnings": [],
        }

        seen_mountpoints = set()

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 4:
                data["warnings"].append(f"Line {line_num}: Malformed fstab entry '{line}'")
                continue

            spec = parts[0]
            mountpoint = parts[1]
            vfstype = parts[2]
            options = parts[3]
            dump = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
            passno = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0

            # Check for duplicate mountpoints
            if mountpoint != "none" and mountpoint != "swap" and mountpoint in seen_mountpoints:
                data["warnings"].append(f"Duplicate mountpoint in /etc/fstab: '{mountpoint}'")
            seen_mountpoints.add(mountpoint)

            data["entries"].append({
                "spec": spec,
                "mountpoint": mountpoint,
                "vfstype": vfstype,
                "options": options,
                "dump": dump,
                "passno": passno,
                "line_number": line_num,
            })

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Parsed {len(data['entries'])} entries from /etc/fstab",
        )
