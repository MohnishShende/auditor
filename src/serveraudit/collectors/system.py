"""
System and Operating System collector for Linux Server Audit.
"""

from __future__ import annotations
import os
from pathlib import Path
import platform
import re
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SystemCollector(BaseCollector):
    manifest = CollectorManifest(
        name="system",
        category="system",
        description="Collect Linux distribution, kernel, architecture, uptime, and system identity",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["hostnamectl", "uname -a", "uptime -s", "systemd-detect-virt"],
        outputs=["hostname", "os", "kernel", "uptime", "virtualization", "boot_mode"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "hostname": platform.node(),
            "pretty_hostname": None,
            "os": {
                "name": None,
                "version": None,
                "id": None,
                "id_like": [],
                "codename": None,
                "pretty_name": None,
            },
            "kernel": {
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "cmdline": None,
            },
            "uptime_seconds": None,
            "last_boot": None,
            "timezone": None,
            "virtualization": "none",
            "is_container": False,
            "boot_mode": "unknown",
            "machine_id": None,
            "boot_id": None,
        }

        # 1. Parse /etc/os-release
        os_release = executor.read_file("/etc/os-release")
        if os_release:
            for line in os_release.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip("\"'")
                if k == "NAME":
                    data["os"]["name"] = v
                elif k == "VERSION":
                    data["os"]["version"] = v
                elif k == "ID":
                    data["os"]["id"] = v
                elif k == "ID_LIKE":
                    data["os"]["id_like"] = v.split()
                elif k == "VERSION_CODENAME":
                    data["os"]["codename"] = v
                elif k == "PRETTY_NAME":
                    data["os"]["pretty_name"] = v

        if not data["os"]["pretty_name"]:
            data["os"]["pretty_name"] = f"{platform.system()} {platform.release()}"

        # 2. Kernel cmdline
        cmdline = executor.read_file("/proc/cmdline")
        if cmdline:
            data["kernel"]["cmdline"] = cmdline.strip()

        # 3. Uptime and last boot
        uptime_file = executor.read_file("/proc/uptime")
        if uptime_file:
            try:
                data["uptime_seconds"] = float(uptime_file.split()[0])
            except (ValueError, IndexError):
                pass

        # 4. Machine and Boot ID
        m_id = executor.read_file("/etc/machine-id") or executor.read_file("/var/lib/dbus/machine-id")
        if m_id:
            data["machine_id"] = m_id.strip()

        b_id = executor.read_file("/proc/sys/kernel/random/boot_id")
        if b_id:
            data["boot_id"] = b_id.strip()

        # 5. Boot mode: UEFI vs BIOS
        if Path("/sys/firmware/efi").exists():
            data["boot_mode"] = "UEFI"
        else:
            data["boot_mode"] = "BIOS"

        # 6. Virtualization
        virt_res = executor.run(["systemd-detect-virt"])
        if virt_res.success and virt_res.stdout.strip():
            virt = virt_res.stdout.strip()
            data["virtualization"] = virt
            if virt in ("docker", "lxc", "podman", "containerd"):
                data["is_container"] = True

        # 7. Timezone
        if Path("/etc/timezone").exists():
            tz = executor.read_file("/etc/timezone")
            if tz:
                data["timezone"] = tz.strip()

        # 8. hostnamectl information
        hctl = executor.run(["hostnamectl", "status"])
        if hctl.success:
            for line in hctl.stdout.splitlines():
                if ":" in line:
                    hk, hv = [x.strip() for x in line.split(":", 1)]
                    if "Pretty hostname" in hk:
                        data["pretty_hostname"] = hv
                    elif "Time zone" in hk:
                        data["timezone"] = hv.split()[0] if hv else None

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="System identity collected successfully",
        )
