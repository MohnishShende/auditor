"""
Btrfs filesystems and subvolumes collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class BtrfsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="btrfs",
        category="storage",
        description="Inspect Btrfs filesystems, devices, subvolumes, and profiles",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["btrfs filesystem show", "btrfs subvolume list /"],
        outputs=["filesystems", "subvolumes"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("btrfs"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="btrfs utility (btrfs-progs) not installed",
            )

        data: Dict[str, Any] = {
            "filesystems": [],
            "subvolumes": [],
        }

        # btrfs filesystem show
        show_res = executor.run(["btrfs", "filesystem", "show"])
        if show_res.success and show_res.stdout.strip():
            for block in show_res.stdout.strip().split("Label: "):
                if not block.strip():
                    continue
                lines = block.strip().splitlines()
                first_line = lines[0]
                label_match = re.match(r"^'?(.*?)'?\s+uuid:\s+([0-9a-fA-F-]+)", first_line)
                label = label_match.group(1) if label_match else None
                uuid = label_match.group(2) if label_match else None

                devs = []
                for line in lines[1:]:
                    if "devid" in line:
                        dev_match = re.search(r"path\s+(\S+)", line)
                        if dev_match:
                            devs.append(dev_match.group(1))

                data["filesystems"].append({
                    "label": label,
                    "uuid": uuid,
                    "devices": devs,
                })

        if not data["filesystems"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="No Btrfs filesystems found",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['filesystems'])} Btrfs filesystems",
        )
