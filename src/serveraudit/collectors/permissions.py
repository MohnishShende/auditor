"""
Targeted file permissions, sensitive paths, and SUID binary security collector.
"""

from __future__ import annotations
import os
from pathlib import Path
import stat
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class PermissionsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="permissions",
        category="security",
        description="Targeted inspection of sensitive path permissions (/etc/shadow, /etc/sudoers, docker.sock) and SUID binaries",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["stat -c '%a %U %G %n' <paths>"],
        outputs=["sensitive_files", "suid_binaries", "permission_warnings"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "sensitive_files": [],
            "suid_binaries": [],
            "permission_warnings": [],
        }

        # 1. Inspect targeted security-sensitive paths
        targets = [
            ("/etc/shadow", 0o640, "shadow"),
            ("/etc/gshadow", 0o640, "shadow"),
            ("/etc/passwd", 0o644, "root"),
            ("/etc/group", 0o644, "root"),
            ("/etc/sudoers", 0o440, "root"),
            ("/etc/ssh/sshd_config", 0o600, "root"),
            ("/root", 0o700, "root"),
            ("/var/run/docker.sock", 0o660, "root"),
        ]

        for path_str, max_perm, expected_owner in targets:
            p = Path(path_str)
            if not p.exists():
                continue
            try:
                st = p.stat()
                mode = stat.S_IMODE(st.st_mode)
                oct_mode = oct(mode)
                
                # Check for world-writable or overly permissive permissions
                is_world_writable = bool(mode & stat.S_IWOTH)
                is_overly_permissive = mode > max_perm

                entry = {
                    "path": path_str,
                    "permissions": oct_mode,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "world_writable": is_world_writable,
                }
                data["sensitive_files"].append(entry)

                if is_world_writable:
                    data["permission_warnings"].append(f"Security Alert: {path_str} is WORLD WRITABLE ({oct_mode})")
                elif is_overly_permissive:
                    data["permission_warnings"].append(f"Notice: {path_str} permissions ({oct_mode}) exceed standard ({oct(max_perm)})")

            except Exception:
                pass

        # 2. Targeted search for SUID binaries in standard system directories
        search_dirs = [Path("/bin"), Path("/sbin"), Path("/usr/bin"), Path("/usr/sbin")]
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            try:
                for item in sdir.iterdir():
                    if item.is_file() and not item.is_symlink():
                        try:
                            st = item.stat()
                            if st.st_mode & stat.S_ISUID:
                                data["suid_binaries"].append({
                                    "path": str(item),
                                    "permissions": oct(stat.S_IMODE(st.st_mode)),
                                    "uid": st.st_uid,
                                })
                        except Exception:
                            continue
            except Exception:
                continue

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Audited {len(data['sensitive_files'])} sensitive file paths and found {len(data['suid_binaries'])} SUID binaries",
        )
