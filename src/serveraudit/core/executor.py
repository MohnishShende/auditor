"""
Observational command and filesystem executor for Linux Server Audit.
Strictly ensures no state-modifying commands execute.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

from .privileges import PrivilegeManager


# Strict safety denylist of standalone binaries that modify state
FORBIDDEN_BINARIES = {
    "rm", "rmdir", "mkfs", "mke2fs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
    "dd", "fdisk", "parted", "gdisk", "wipefs", "shred",
    "reboot", "poweroff", "shutdown", "halt", "init",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "chage",
    "chmod", "chown", "chgrp",
    "mount", "umount",
}

# Strict safety denylist of command patterns that modify state
FORBIDDEN_PATTERNS = [
    r"\bapt(-get)?\s+(install|remove|purge|autoremove)\b",
    r"\bdpkg\s+-(i|r|P|--install|--remove|--purge)\b",
    r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask)\b",
    r"\bdocker\s+(run|stop|restart|rm|rmi|kill|pause|unpause|system\s+prune|volume\s+rm|network\s+rm)\b",
    r"\bcryptsetup\s+(open|close|luksFormat|luksOpen|luksClose)\b",
    r"\biptables\s+-[ADIFNX]\b",
    r"\bnft\s+(add|delete|flush|insert)\b",
    r"\bufw\s+(enable|disable|allow|deny|delete|insert|reload|reset)\b",
]


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

        if binary in FORBIDDEN_BINARIES:
            return False, f"Forbidden state-modifying binary: '{binary}'"

        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, cmd_str, re.IGNORECASE):
                return False, f"Forbidden state-modifying command pattern: '{pattern}'"

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
                error_message="Timeout",
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

    def read_file(
        self,
        path: Path | str,
        use_sudo: bool = False,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> Optional[str]:
        """Reads file contents safely without modification."""
        p = Path(path)
        if not use_sudo:
            try:
                if p.is_file():
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        return f.read(max_bytes)
            except (PermissionError, FileNotFoundError, OSError):
                pass

        # If unprivileged read failed or sudo requested
        if use_sudo and self.privileges.can_elevate:
            cat_out = self.run(["cat", str(p)], use_sudo=True)
            if cat_out.success:
                return cat_out.stdout[:max_bytes]

        return None
