"""
Storage block devices and partition topology collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class StorageCollector(BaseCollector):
    manifest = CollectorManifest(
        name="storage",
        category="storage",
        description="Collect block devices, partitions, rotational state, media type, and disk topology",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["lsblk -J -b -o NAME,PATH,TYPE,SIZE,ROTA,MODEL,SERIAL,WWN,FSTYPE,LABEL,UUID,MOUNTPOINT,PKNAME"],
        outputs=["disks", "blockdevices", "partitions"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("lsblk"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="lsblk utility not found",
            )

        cmd = [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,PATH,TYPE,SIZE,ROTA,MODEL,SERIAL,WWN,FSTYPE,LABEL,UUID,MOUNTPOINT,PKNAME,STATE",
        ]
        res = executor.run(cmd)
        if not res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                error=res.stderr,
                message="lsblk execution failed",
            )

        data: Dict[str, Any] = {
            "disks": [],
            "partitions": [],
            "blockdevices": [],
        }

        try:
            lsblk_json = json.loads(res.stdout)
            devices = lsblk_json.get("blockdevices", [])

            def process_dev(dev: Dict[str, Any], parent_disk: str = None) -> Dict[str, Any]:
                size_bytes = dev.get("size")
                if isinstance(size_bytes, str) and size_bytes.isdigit():
                    size_bytes = int(size_bytes)

                rota = dev.get("rota")
                if isinstance(rota, str):
                    rota = rota == "1" or rota.lower() == "true"
                elif isinstance(rota, int):
                    rota = rota == 1

                dtype = dev.get("type", "unknown")
                path = dev.get("path") or f"/dev/{dev.get('name')}"

                # Classify media type
                media = "unknown"
                if "nvme" in path:
                    media = "nvme"
                elif rota:
                    media = "hdd"
                elif not rota and dtype == "disk":
                    media = "ssd"

                item = {
                    "name": dev.get("name"),
                    "path": path,
                    "type": dtype,
                    "media": media,
                    "size_bytes": size_bytes,
                    "size_formatted": Normalizer.format_bytes(size_bytes),
                    "rotational": rota,
                    "model": (dev.get("model") or "").strip() or None,
                    "serial": (dev.get("serial") or "").strip() or None,
                    "wwn": (dev.get("wwn") or "").strip() or None,
                    "fstype": dev.get("fstype"),
                    "label": dev.get("label"),
                    "uuid": dev.get("uuid"),
                    "mountpoint": dev.get("mountpoint"),
                    "parent": parent_disk or dev.get("pkname"),
                    "state": dev.get("state"),
                    "children": [],
                }

                if dtype == "disk":
                    data["disks"].append(item)
                elif dtype in ("part", "partition"):
                    data["partitions"].append(item)

                data["blockdevices"].append(item)

                # Process recursive partition tree
                for child in dev.get("children", []):
                    child_item = process_dev(child, parent_disk=item["name"])
                    item["children"].append(child_item)

                return item

            for root_dev in devices:
                process_dev(root_dev)

        except Exception as e:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.PARTIAL,
                error=str(e),
                message=f"Error parsing lsblk output: {str(e)}",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['disks'])} physical disks and {len(data['partitions'])} partitions",
        )
