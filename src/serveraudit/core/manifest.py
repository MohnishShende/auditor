"""
Audit manifest generation and provenance tracking for Linux Server Audit.
"""

from __future__ import annotations
import getpass
import os
import platform
from typing import Any, Dict, List, Optional

from .. import __version__, __schema_version__
from .collector import CollectorResult, CollectorStatus
from .normalizer import Normalizer


class ManifestGenerator:
    """Creates the audit manifest recording complete provenance and collector states."""

    @staticmethod
    def generate(
        hostname: str,
        profile: str,
        duration_seconds: float,
        results: Dict[str, CollectorResult],
        privileges_available: bool,
        operating_user: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate manifest dictionary."""
        user = operating_user or getpass.getuser()
        collectors_status: Dict[str, str] = {}
        errors: Dict[str, Dict[str, Any]] = {}

        for name, res in results.items():
            collectors_status[name] = res.status.value
            if res.status != CollectorStatus.SUCCESS or res.error:
                errors[name] = {
                    "status": res.status.value,
                    "error": res.error,
                    "message": res.message,
                }

        ts = (extra_metadata.get("timestamp") if extra_metadata else None) or Normalizer.iso_timestamp()

        manifest = {
            "tool": "serveraudit",
            "version": __version__,
            "schema": __schema_version__,
            "profile": profile,
            "timestamp": ts,
            "hostname": hostname,
            "duration_seconds": round(duration_seconds, 4),
            "operating_user": user,
            "privileges_available": privileges_available,
            "network_access": False,
            "intentional_system_modification": False,
            "collectors": collectors_status,
            "errors": errors if errors else None,
        }

        if extra_metadata:
            for k, v in extra_metadata.items():
                if k not in manifest:
                    manifest[k] = v

        return manifest
