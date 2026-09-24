"""
Users, groups, sudoers, and account security collector for Linux Server Audit.
Strictly NEVER collects or exports password hashes.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Set

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class UsersCollector(BaseCollector):
    manifest = CollectorManifest(
        name="users",
        category="security",
        description="Collect local users, groups, sudoers memberships, UID 0 accounts, and login shells",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["passwd -S -a"],
        outputs=["users", "human_users", "sudo_users", "uid0_accounts", "groups"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "users": [],
            "human_users": [],
            "sudo_users": [],
            "uid0_accounts": [],
            "groups": [],
        }

        # 1. Parse /etc/group
        groups_content = executor.read_file("/etc/group")
        group_members: Dict[str, List[str]] = {}
        if groups_content:
            for line in groups_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 3:
                    gname = parts[0]
                    gid = int(parts[2]) if parts[2].isdigit() else -1
                    members = parts[3].split(",") if len(parts) > 3 and parts[3] else []
                    group_members[gname] = members
                    data["groups"].append({
                        "name": gname,
                        "gid": gid,
                        "members": members,
                    })

        sudo_groups = {"sudo", "wheel", "admin"}
        sudo_usernames: Set[str] = set()
        for sg in sudo_groups:
            if sg in group_members:
                sudo_usernames.update(group_members[sg])

        # 2. Check password status (L/P/NP) without hashes from /etc/shadow
        shadow_status: Dict[str, str] = {}
        shadow_content = executor.read_file("/etc/shadow", use_sudo=True)
        if shadow_content:
            for line in shadow_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 2:
                    uname = parts[0]
                    pwd_field = parts[1]
                    if pwd_field in ("!", "*", "!!", ""):
                        shadow_status[uname] = "LOCKED"
                    elif pwd_field.startswith("!"):
                        shadow_status[uname] = "LOCKED"
                    else:
                        shadow_status[uname] = "ACTIVE_PASSWORD"

        # 3. Parse /etc/passwd
        passwd_content = executor.read_file("/etc/passwd")
        if not passwd_content:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                message="Unable to read /etc/passwd",
            )

        for line in passwd_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                uid = int(parts[2]) if parts[2].isdigit() else -1
                gid = int(parts[3]) if parts[3].isdigit() else -1
                comment = parts[4]
                home = parts[5]
                shell = parts[6]

                is_human = (uid >= 1000 and uid < 60000) and shell not in (
                    "/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/usr/bin/false"
                )
                has_sudo = username in sudo_usernames or uid == 0

                user_info = {
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "comment": comment,
                    "home": home,
                    "shell": shell,
                    "is_human": is_human,
                    "has_sudo": has_sudo,
                    "password_status": shadow_status.get(username, "UNKNOWN"),
                }

                data["users"].append(user_info)

                if uid == 0:
                    data["uid0_accounts"].append(user_info)
                if is_human:
                    data["human_users"].append(user_info)
                if has_sudo:
                    data["sudo_users"].append(user_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['users'])} total accounts ({len(data['human_users'])} human, {len(data['sudo_users'])} with sudo)",
        )
