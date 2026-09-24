"""
Boot chain, bootloader, GRUB configuration, and EFI boot collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class BootCollector(BaseCollector):
    manifest = CollectorManifest(
        name="boot",
        category="system",
        description="Inspect bootloader, GRUB default parameters, EFI boot variables, and kernel command line",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["efibootmgr -v"],
        outputs=["boot_mode", "grub_default", "installed_kernels", "efi_entries"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "boot_mode": "UEFI" if Path("/sys/firmware/efi").exists() else "BIOS",
            "grub_default": {},
            "installed_kernels": [],
            "efi_entries": [],
        }

        # 1. /etc/default/grub parameters
        grub_content = executor.read_file("/etc/default/grub")
        if grub_content:
            for line in grub_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data["grub_default"][k.strip()] = v.strip("\"'")

        # 2. Installed kernels in /boot
        boot_dir = Path("/boot")
        if boot_dir.exists():
            try:
                for f in sorted(boot_dir.glob("vmlinuz-*")):
                    if f.is_file():
                        data["installed_kernels"].append(f.name.replace("vmlinuz-", ""))
            except Exception:
                pass

        # 3. efibootmgr
        if data["boot_mode"] == "UEFI" and executor.which("efibootmgr"):
            efi_res = executor.run(["efibootmgr"], use_sudo=True)
            if efi_res.success and efi_res.stdout:
                for line in efi_res.stdout.splitlines():
                    if line.startswith("Boot0") or line.startswith("BootCurrent") or line.startswith("BootOrder"):
                        data["efi_entries"].append(line.strip())

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Boot chain documented (Boot Mode: {data['boot_mode']}, {len(data['installed_kernels'])} installed kernels)",
        )
