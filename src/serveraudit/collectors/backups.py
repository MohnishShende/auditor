"""
Backup software and snapshot services detection collector for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class BackupsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="backups",
        category="system",
        description="Detect installed backup tooling (Restic, Borg, Duplicati, Rclone) and snapshot services",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["restic version", "borg --version", "rclone version"],
        outputs=["installed_tools", "backup_services"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "installed_tools": [],
            "active_services": [],
        }

        backup_binaries = [
            ("restic", ["restic", "version"]),
            ("borgbackup", ["borg", "--version"]),
            ("rclone", ["rclone", "version"]),
            ("rsync", ["rsync", "--version"]),
            ("duplicity", ["duplicity", "--version"]),
            ("sanoid", ["sanoid", "--version"]),
            ("btrbk", ["btrbk", "--version"]),
        ]

        for name, cmd in backup_binaries:
            if executor.which(cmd[0]):
                res = executor.run(cmd)
                version_str = res.stdout.splitlines()[0] if res.success and res.stdout else "installed"
                data["installed_tools"].append({
                    "name": name,
                    "binary": cmd[0],
                    "version": version_str.strip(),
                })

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['installed_tools'])} backup tools on system",
        )
