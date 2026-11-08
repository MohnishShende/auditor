"""
Privilege and elevated execution management for Linux Server Audit.
"""

from __future__ import annotations
from enum import Enum
import os
import shutil
import subprocess
from typing import Dict, Any


class AuditMode(str, Enum):
    """Audit privilege modes."""
    USER = "user"
    SUDO = "sudo"


class PrivilegeManager:
    """Detects and validates elevation capabilities according to AuditMode."""

    def __init__(self, mode: AuditMode = AuditMode.USER) -> None:
        self.mode: AuditMode = mode
        self._is_root: bool = self._check_is_root()

        # USER mode hard invariant:
        # Zero sudo subprocesses may be spawned, no capability probe, no lazy detection.
        if self.mode == AuditMode.USER:
            self._has_sudo: bool = False
            self._sudo_validated: bool = False
        else:
            # SUDO mode: If root, sudo is not needed; if non-root, validate_sudo() handles elevation check
            self._has_sudo = False
            self._sudo_validated = False

    @staticmethod
    def _check_is_root() -> bool:
        """Check if currently executing with EUID 0 (root)."""
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return False

    def validate_sudo(self) -> bool:
        """
        In SUDO mode, validate sudo access once at startup.
        If non-root, runs interactive `sudo -v` once.
        In USER mode, strictly does nothing and returns False.
        """
        if self.mode == AuditMode.USER:
            self._has_sudo = False
            return False

        if self._is_root:
            self._has_sudo = True
            self._sudo_validated = True
            return True

        if shutil.which("sudo") is None:
            self._has_sudo = False
            self._sudo_validated = True
            return False

        try:
            # Interactive sudo -v once at startup to authenticate and cache timestamp
            result = subprocess.run(["sudo", "-v"], check=False)
            self._has_sudo = (result.returncode == 0)
        except Exception:
            self._has_sudo = False

        self._sudo_validated = True
        return self._has_sudo

    @property
    def is_root(self) -> bool:
        return self._is_root

    @property
    def has_sudo(self) -> bool:
        return self._has_sudo

    @property
    def can_elevate(self) -> bool:
        return self._is_root or self._has_sudo

    def get_status(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "is_root": self._is_root,
            "has_sudo": self._has_sudo,
            "can_elevate": self.can_elevate,
        }
