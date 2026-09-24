"""
File sharing (Samba shares and NFS exports) collector for Linux Server Audit.
Strictly NEVER exports credentials or passwords.
"""

from __future__ import annotations
import configparser
import io
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SharingCollector(BaseCollector):
    manifest = CollectorManifest(
        name="sharing",
        category="services",
        description="Inspect Samba (SMB) shares and NFS export definitions and access policies",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["exportfs -v", "testparm -s"],
        outputs=["samba_shares", "nfs_exports"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "samba_shares": [],
            "nfs_exports": [],
        }

        # 1. Samba (/etc/samba/smb.conf)
        smb_conf = executor.read_file("/etc/samba/smb.conf", use_sudo=True)
        if smb_conf:
            try:
                # Parse ini-style smb.conf
                cfg = configparser.ConfigParser(allow_no_value=True, strict=False)
                cfg.read_string(smb_conf)
                for section in cfg.sections():
                    if section.lower() in ("global", "homes", "printers"):
                        continue
                    path = cfg.get(section, "path", fallback=None)
                    read_only = cfg.get(section, "read only", fallback="yes")
                    guest_ok = cfg.get(section, "guest ok", fallback="no")
                    data["samba_shares"].append({
                        "name": section,
                        "path": path,
                        "read_only": read_only.lower() in ("yes", "true", "1"),
                        "guest_ok": guest_ok.lower() in ("yes", "true", "1"),
                    })
            except Exception:
                pass

        # 2. NFS Exports (/etc/exports)
        nfs_exports = executor.read_file("/etc/exports", use_sudo=True)
        if nfs_exports:
            for line in nfs_exports.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) >= 2:
                    data["nfs_exports"].append({
                        "path": parts[0],
                        "clients_and_options": parts[1],
                    })

        if not data["samba_shares"] and not data["nfs_exports"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="No active Samba or NFS shares configured",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['samba_shares'])} Samba shares and {len(data['nfs_exports'])} NFS exports",
        )
