"""
Installed packages, pending security updates, and package managers (APT/dpkg, Snap, Flatpak) collector.
Strictly observational; never installs or updates packages.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class PackagesCollector(BaseCollector):
    manifest = CollectorManifest(
        name="packages",
        category="system",
        description="Inspect installed package counts, manual vs auto packages, pending updates, and security updates",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["dpkg-query -f '${binary:Package}\t${Version}\t${Status}\n' -W", "apt-mark showmanual", "snap list", "flatpak list"],
        outputs=["installed_count", "manual_count", "pending_updates", "security_updates", "snap_packages", "flatpak_packages"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "package_manager": "unknown",
            "installed_count": 0,
            "manual_count": 0,
            "pending_updates_count": 0,
            "pending_security_updates_count": 0,
            "reboot_required": Path("/var/run/reboot-required").exists(),
            "snap_packages": [],
            "flatpak_packages": [],
            "packages_sample": [],
        }

        # 1. Debian/Ubuntu (dpkg/apt)
        if executor.which("dpkg-query"):
            data["package_manager"] = "dpkg/apt"
            dpkg_res = executor.run(["dpkg-query", "-W", "-f", "${binary:Package}\t${Version}\t${Status}\n"])
            if dpkg_res.success and dpkg_res.stdout:
                lines = [l for l in dpkg_res.stdout.splitlines() if "install ok installed" in l]
                data["installed_count"] = len(lines)
                for line in lines[:20]:  # Sample first 20 for summary
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        data["packages_sample"].append({
                            "package": parts[0],
                            "version": parts[1],
                        })

        if executor.which("apt-mark"):
            manual_res = executor.run(["apt-mark", "showmanual"])
            if manual_res.success and manual_res.stdout:
                data["manual_count"] = len(manual_res.stdout.splitlines())

        # 2. Check pending updates via /var/lib/update-notifier/updates-available or apt-get -s upgrade
        updates_avail = executor.read_file("/var/lib/update-notifier/updates-available")
        if updates_avail:
            up_m = re.search(r"(\d+)\s+updates\s+can\s+be\s+applied", updates_avail, re.IGNORECASE)
            if up_m:
                data["pending_updates_count"] = int(up_m.group(1))
            sec_m = re.search(r"(\d+)\s+of\s+these\s+updates\s+are\s+security\s+updates", updates_avail, re.IGNORECASE)
            if sec_m:
                data["pending_security_updates_count"] = int(sec_m.group(1))

        # 3. Snap packages
        if executor.which("snap"):
            snap_res = executor.run(["snap", "list"])
            if snap_res.success and snap_res.stdout:
                for line in snap_res.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        data["snap_packages"].append({
                            "name": parts[0],
                            "version": parts[1],
                            "rev": parts[2],
                            "tracking": parts[3] if len(parts) > 3 else "",
                            "publisher": parts[4] if len(parts) > 4 else "",
                        })

        # 4. Flatpak packages
        if executor.which("flatpak"):
            flat_res = executor.run(["flatpak", "list", "--columns=name,application,version"])
            if flat_res.success and flat_res.stdout:
                for line in flat_res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        data["flatpak_packages"].append({
                            "name": parts[0],
                            "application": parts[1],
                            "version": parts[2] if len(parts) > 2 else "",
                        })

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {data['installed_count']} installed packages ({data['pending_security_updates_count']} pending security updates, reboot required: {data['reboot_required']})",
        )
