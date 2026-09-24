"""
Linux security controls (AppArmor, SELinux, Seccomp, ASLR, Lockdown, sysctl) collector.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SecurityCollector(BaseCollector):
    manifest = CollectorManifest(
        name="security",
        category="security",
        description="Inspect Linux LSMs (AppArmor/SELinux), Kernel Lockdown, ASLR, Seccomp, and sysctl hardening",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["aa-status", "sestatus"],
        outputs=["apparmor", "selinux", "aslr", "lockdown", "sysctl_hardening"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "apparmor": {
                "installed": executor.which("aa-status") is not None,
                "enabled": False,
                "profiles_enforce": 0,
                "profiles_complain": 0,
            },
            "selinux": {
                "installed": executor.which("sestatus") is not None,
                "enabled": False,
                "mode": "disabled",
            },
            "aslr": "unknown",
            "lockdown": "unknown",
            "sysctl_hardening": {},
        }

        # 1. AppArmor
        if data["apparmor"]["installed"]:
            aa_res = executor.run(["aa-status"], use_sudo=True)
            if aa_res.success and aa_res.stdout:
                data["apparmor"]["enabled"] = True
                for line in aa_res.stdout.splitlines():
                    if "profiles are in enforce mode" in line:
                        data["apparmor"]["profiles_enforce"] = int(line.split()[0])
                    elif "profiles are in complain mode" in line:
                        data["apparmor"]["profiles_complain"] = int(line.split()[0])

        # 2. SELinux
        if data["selinux"]["installed"]:
            se_res = executor.run(["sestatus"], use_sudo=True)
            if se_res.success and se_res.stdout:
                for line in se_res.stdout.splitlines():
                    if "SELinux status:" in line:
                        data["selinux"]["enabled"] = "enabled" in line
                    elif "Current mode:" in line:
                        data["selinux"]["mode"] = line.split(":", 1)[1].strip()

        # 3. ASLR
        aslr_val = executor.read_file("/proc/sys/kernel/randomize_va_space")
        if aslr_val:
            aslr_code = aslr_val.strip()
            data["aslr"] = {
                "0": "disabled",
                "1": "conservative (stack/vdso/mmap)",
                "2": "full (stack/vdso/mmap/brk)",
            }.get(aslr_code, f"custom ({aslr_code})")

        # 4. Kernel Lockdown
        lockdown_val = executor.read_file("/sys/kernel/security/lockdown")
        if lockdown_val:
            data["lockdown"] = lockdown_val.strip()

        # 5. Core sysctl security flags
        sysctls = [
            ("net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"),
            ("net.ipv4.conf.all.rp_filter", "/proc/sys/net/ipv4/conf/all/rp_filter"),
            ("net.ipv4.conf.all.accept_redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects"),
            ("kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"),
            ("kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"),
            ("kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"),
            ("fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks"),
            ("fs.protected_symlinks", "/proc/sys/fs/protected_symlinks"),
            ("fs.suid_dumpable", "/proc/sys/fs/suid_dumpable"),
        ]
        for key, path in sysctls:
            val = executor.read_file(path)
            if val:
                data["sysctl_hardening"][key] = val.strip()

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Linux security controls, LSMs, and sysctl posture inspected",
        )
