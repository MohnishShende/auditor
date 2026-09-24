"""
Filesystems, mount points, utilization, and inode collector for Linux Server Audit.
"""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class FilesystemsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="filesystems",
        category="storage",
        description="Collect mounted filesystems, mount options, disk utilization, and inode metrics",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["df -PT -B1", "findmnt -J -l -o TARGET,SOURCE,FSTYPE,OPTIONS"],
        outputs=["mounts", "filesystems", "utilization"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "mounts": [],
            "network_mounts": [],
            "virtual_mounts": [],
        }

        # 1. Gather mount options from findmnt -J
        mount_options_map: Dict[str, str] = {}
        if executor.which("findmnt"):
            findmnt_res = executor.run(["findmnt", "-J", "-l", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
            if findmnt_res.success and findmnt_res.stdout:
                try:
                    fm_json = json.loads(findmnt_res.stdout)
                    for item in fm_json.get("filesystems", []):
                        target = item.get("target")
                        if target:
                            mount_options_map[target] = item.get("options", "")
                except Exception:
                    pass

        # 2. Gather sizes from df -PT -B1
        df_res = executor.run(["df", "-PT", "-B1"])
        if not df_res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                error=df_res.stderr,
                message="df command failed",
            )

        # 3. Gather inode metrics from df -PTi
        df_inodes_map: Dict[str, Dict[str, Any]] = {}
        df_i_res = executor.run(["df", "-PTi"])
        if df_i_res.success:
            for line in df_i_res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    target = parts[6] if len(parts) > 6 else parts[5]
                    try:
                        df_inodes_map[target] = {
                            "total": int(parts[2]) if parts[2].isdigit() else 0,
                            "used": int(parts[3]) if parts[3].isdigit() else 0,
                            "free": int(parts[4]) if parts[4].isdigit() else 0,
                            "percent_used": float(parts[5].rstrip("%")) if parts[5].rstrip("%").isdigit() else 0.0,
                        }
                    except (ValueError, IndexError):
                        pass

        # Parse df -PT -B1 output
        lines = df_res.stdout.splitlines()
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 7:
                    continue
                source = parts[0]
                fstype = parts[1]
                try:
                    total_bytes = int(parts[2])
                    used_bytes = int(parts[3])
                    avail_bytes = int(parts[4])
                    pct_str = parts[5].rstrip("%")
                    percent_used = float(pct_str) if pct_str.isdigit() else 0.0
                    target = " ".join(parts[6:])
                except (ValueError, IndexError):
                    continue

                options = mount_options_map.get(target, "")
                inodes = df_inodes_map.get(target, {"total": 0, "used": 0, "free": 0, "percent_used": 0.0})

                mount_info = {
                    "source": source,
                    "target": target,
                    "fstype": fstype,
                    "total_bytes": total_bytes,
                    "total_formatted": Normalizer.format_bytes(total_bytes),
                    "used_bytes": used_bytes,
                    "used_formatted": Normalizer.format_bytes(used_bytes),
                    "available_bytes": avail_bytes,
                    "available_formatted": Normalizer.format_bytes(avail_bytes),
                    "percent_used": percent_used,
                    "options": options,
                    "read_only": "ro" in options.split(","),
                    "inodes": inodes,
                }

                if fstype in ("nfs", "nfs4", "cifs", "smb3", "sshfs"):
                    data["network_mounts"].append(mount_info)
                elif fstype in ("tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "overlay", "squashfs"):
                    data["virtual_mounts"].append(mount_info)
                else:
                    data["mounts"].append(mount_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['mounts'])} physical and {len(data['network_mounts'])} network filesystems",
        )
