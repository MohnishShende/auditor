"""
Disk and volume encryption (LUKS, dm-crypt, crypttab) collector for Linux Server Audit.
Strictly NEVER collects passwords, passphrases, or master keys.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class EncryptionCollector(BaseCollector):
    manifest = CollectorManifest(
        name="encryption",
        category="storage",
        description="Inspect LUKS / dm-crypt active mappings, cipher, key size, and crypttab configuration",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["cryptsetup status <name>", "dmsetup ls --target crypt"],
        outputs=["encrypted_volumes", "crypttab_entries"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "encrypted_volumes": [],
            "crypttab_entries": [],
        }

        # 1. Parse /etc/crypttab (safe structure only)
        crypttab_content = executor.read_file("/etc/crypttab", use_sudo=True)
        if crypttab_content:
            for line in crypttab_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    data["crypttab_entries"].append({
                        "target_name": parts[0],
                        "source_device": parts[1],
                        "has_keyfile": len(parts) > 2 and parts[2] not in ("none", "-"),
                        "options": parts[3] if len(parts) > 3 else "",
                    })

        # 2. Discover active crypt mappings via dmsetup or /dev/mapper
        active_crypts: List[str] = []
        if executor.which("dmsetup"):
            dm_res = executor.run(["dmsetup", "ls", "--target", "crypt"], use_sudo=True)
            if dm_res.success and dm_res.stdout.strip():
                for line in dm_res.stdout.splitlines():
                    if line.strip():
                        target_name = line.split()[0]
                        active_crypts.append(target_name)

        # 3. Query cryptsetup status for each active device
        if executor.which("cryptsetup"):
            for target in active_crypts:
                cs_res = executor.run(["cryptsetup", "status", target], use_sudo=True)
                if cs_res.success and cs_res.stdout:
                    vol_data: Dict[str, Any] = {
                        "target_name": target,
                        "device_mapper_path": f"/dev/mapper/{target}",
                        "type": "crypt",
                        "cipher": None,
                        "keysize_bits": None,
                        "underlying_device": None,
                        "offset_sectors": None,
                        "size_sectors": None,
                        "flags": [],
                    }
                    for line in cs_res.stdout.splitlines():
                        if ":" in line:
                            k, v = [x.strip() for x in line.split(":", 1)]
                            if k == "type":
                                vol_data["type"] = v
                            elif k == "cipher":
                                vol_data["cipher"] = v
                            elif k == "keysize":
                                vol_data["keysize_bits"] = int(v.split()[0]) if v.split()[0].isdigit() else None
                            elif k == "device":
                                vol_data["underlying_device"] = v
                            elif k == "offset":
                                vol_data["offset_sectors"] = int(v.split()[0]) if v.split()[0].isdigit() else None
                            elif k == "size":
                                vol_data["size_sectors"] = int(v.split()[0]) if v.split()[0].isdigit() else None
                            elif k == "flags":
                                vol_data["flags"] = v.split()

                    data["encrypted_volumes"].append(vol_data)

        if not data["encrypted_volumes"] and not data["crypttab_entries"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="No encrypted storage volumes or crypttab entries detected",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['encrypted_volumes'])} active encrypted volumes",
        )
