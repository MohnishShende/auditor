"""
Privilege and elevated execution management for Linux Server Audit.
"""

from __future__ import annotations
import os
import shutil
import subprocess
from typing import Dict, Any


class PrivilegeManager:
    """Detects and validates elevation capabilities."""

    def __init__(self) -> None:
        self._is_root: bool = self._check_is_root()
        self._has_sudo: bool = self._check_has_sudo()

    @staticmethod
    def _check_is_root() -> bool:
        """Check if currently executing with EUID 0 (root)."""
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return False

    @staticmethod
    def _check_has_sudo() -> bool:
        """Check if sudo is installed and credentials are non-interactively valid."""
        if shutil.which("sudo") is None:
            return False
        try:
            # -n: non-interactive (fails if password is required)
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

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
            "is_root": self._is_root,
            "has_sudo": self._has_sudo,
            "can_elevate": self.can_elevate,
        }
