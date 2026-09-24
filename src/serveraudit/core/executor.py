"""
Observational command and filesystem executor for Linux Server Audit.
Strictly ensures no state-modifying commands execute.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

from .privileges import PrivilegeManager


# Strict safety denylist of commands or subcommands that modify state
FORBIDDEN_COMMANDS = {
    "rm", "rmdir", "mkfs", "mke2fs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
    "dd", "fdisk", "parted", "gdisk", "wipefs", "shred",
    "reboot", "poweroff", "shutdown", "halt", "init",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "chage",
    "chmod", "chown", "chgrp",
    "apt-get install", "apt install", "apt remove", "apt-get remove", "apt purge", "dpkg -i", "dpkg -r",
    "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable", "systemctl disable", "systemctl mask",
    "docker run", "docker stop", "docker restart", "docker rm", "docker rmi", "docker system prune",
    "mount", "umount", "cryptsetup open", "cryptsetup close", "cryptsetup luksFormat",
    "iptables -A", "iptables -D", "iptables -F", "nft add", "nft delete", "ufw enable", "ufw disable", "ufw allow", "ufw deny",
}


@dataclass
class CommandOutput:
    """Result of a command execution."""
    command: List[str]
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    success: bool
    used_sudo: bool
    error_message: Optional[str] = None


@dataclass
class ExecutionLogEntry:
    """Entry for provenance logging."""
    command: str
    returncode: int
    duration_seconds: float
    used_sudo: bool
    success: bool


class CommandExecutor:
    """Executes purely observational commands and reads files safely."""

    def __init__(self, privilege_manager: Optional[PrivilegeManager] = None) -> None:
        self.privileges = privilege_manager or PrivilegeManager()
        self.execution_log: List[ExecutionLogEntry] = []

    def which(self, binary: str) -> Optional[str]:
        """Check if binary exists in PATH."""
        return shutil.which(binary)

    def is_safe_command(self, cmd: List[str]) -> Tuple[bool, Optional[str]]:
        """Verify that the command is strictly observational."""
        if not cmd:
            return False, "Empty command"

        cmd_str = " ".join(cmd).strip()
        binary = Path(cmd[0]).name

        if binary in FORBIDDEN_COMMANDS:
            return False, f"Forbidden state-modifying binary: '{binary}'"

        for forbidden in FORBIDDEN_COMMANDS:
            if forbidden in cmd_str:
                return False, f"Forbidden state-modifying command pattern: '{forbidden}'"

        return True, None

    def run(
        self,
        cmd: List[str],
        use_sudo: bool = False,
        timeout: int = 30,
        check_safety: bool = True,
    ) -> CommandOutput:
        """Executes a command safely without shell=True."""
        if check_safety:
            safe, reason = self.is_safe_command(cmd)
            if not safe:
                return CommandOutput(
                    command=cmd,
                    stdout="",
                    stderr=reason or "Unsafe command blocked",
                    returncode=126,
                    duration_seconds=0.0,
                    success=False,
                    used_sudo=False,
                    error_message=reason,
                )

        final_cmd = list(cmd)
        actual_sudo_used = False

        if use_sudo and not self.privileges.is_root:
            if not self.privileges.has_sudo:
                return CommandOutput(
                    command=cmd,
                    stdout="",
                    stderr="Elevated privileges required but non-interactive sudo unavailable",
                    returncode=126,
                    duration_seconds=0.0,
                    success=False,
                    used_sudo=False,
                    error_message="Sudo unavailable",
                )
            final_cmd = ["sudo", "-n"] + final_cmd
            actual_sudo_used = True

        start_time = time.time()
        try:
            res = subprocess.run(
                final_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration = time.time() - start_time
            success = res.returncode == 0
            
            output = CommandOutput(
                command=final_cmd,
                stdout=res.stdout,
                stderr=res.stderr,
                returncode=res.returncode,
                duration_seconds=duration,
                success=success,
                used_sudo=actual_sudo_used,
            )
            
            self.execution_log.append(
                ExecutionLogEntry(
                    command=" ".join(final_cmd),
                    returncode=res.returncode,
                    duration_seconds=round(duration, 4),
                    used_sudo=actual_sudo_used,
                    success=success,
                )
            )
            return output

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return CommandOutput(
                command=final_cmd,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                returncode=124,
                duration_seconds=duration,
                success=False,
                used_sudo=actual_sudo_used,
                error_message=f"Timeout ({timeout}s)",
            )
        except FileNotFoundError as e:
            duration = time.time() - start_time
            return CommandOutput(
                command=final_cmd,
                stdout="",
                stderr=f"Binary not found: {e.filename or final_cmd[0]}",
                returncode=127,
                duration_seconds=duration,
                success=False,
                used_sudo=actual_sudo_used,
                error_message="Command not found",
            )
        except Exception as e:
            duration = time.time() - start_time
            return CommandOutput(
                command=final_cmd,
                stdout="",
                stderr=str(e),
                returncode=1,
                duration_seconds=duration,
                success=False,
                used_sudo=actual_sudo_used,
                error_message=str(e),
            )

    def read_file(self, filepath: str | Path, use_sudo: bool = False, max_bytes: int = 5_000_000) -> Optional[str]:
        """Safely read a file without modifying atime if possible."""
        p = Path(filepath)
        if not p.exists() and not use_sudo:
            return None

        if use_sudo and not self.privileges.is_root:
            res = self.run(["cat", str(p)], use_sudo=True)
            return res.stdout if res.success else None

        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        except PermissionError:
            if self.privileges.can_elevate:
                res = self.run(["cat", str(p)], use_sudo=True)
                return res.stdout if res.success else None
            return None
        except Exception:
            return None
