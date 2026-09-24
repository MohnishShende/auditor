"""
ZFS storage pools and datasets collector for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class ZfsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="zfs",
        category="storage",
        description="Inspect ZFS storage pools, datasets, compression, and pool health",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["zpool list -H -p -o name,size,alloc,free,cap,health,altroot", "zfs list -H -p -o name,used,avail,refer,mountpoint,compression"],
        outputs=["pools", "datasets"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("zpool") and not executor.which("zfs"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="ZFS utilities (zpool/zfs) not installed",
            )

        data: Dict[str, Any] = {
            "pools": [],
            "datasets": [],
        }

        # 1. zpool list
        zpool_res = executor.run(["zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,cap,health,altroot"])
        if zpool_res.success and zpool_res.stdout.strip():
            for line in zpool_res.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 6:
                    size_b = Normalizer.parse_bytes(parts[1])
                    alloc_b = Normalizer.parse_bytes(parts[2])
                    free_b = Normalizer.parse_bytes(parts[3])
                    data["pools"].append({
                        "name": parts[0],
                        "size_bytes": size_b,
                        "size_formatted": Normalizer.format_bytes(size_b),
                        "alloc_bytes": alloc_b,
                        "alloc_formatted": Normalizer.format_bytes(alloc_b),
                        "free_bytes": free_b,
                        "free_formatted": Normalizer.format_bytes(free_b),
                        "capacity": parts[4],
                        "health": parts[5],
                        "altroot": parts[6] if len(parts) > 6 else "-",
                    })

        # 2. zfs list
        zfs_res = executor.run(["zfs", "list", "-H", "-p", "-o", "name,used,avail,refer,mountpoint,compression"])
        if zfs_res.success and zfs_res.stdout.strip():
            for line in zfs_res.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 6:
                    used_b = Normalizer.parse_bytes(parts[1])
                    avail_b = Normalizer.parse_bytes(parts[2])
                    data["datasets"].append({
                        "name": parts[0],
                        "used_bytes": used_b,
                        "used_formatted": Normalizer.format_bytes(used_b),
                        "avail_bytes": avail_b,
                        "avail_formatted": Normalizer.format_bytes(avail_b),
                        "mountpoint": parts[4],
                        "compression": parts[5],
                    })

        if not data["pools"] and not data["datasets"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="No active ZFS pools or datasets found",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['pools'])} ZFS pools and {len(data['datasets'])} datasets",
        )
