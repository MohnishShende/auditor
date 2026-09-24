"""
Collector interface and models for Linux Server Audit.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import time


class CollectorStatus(str, Enum):
    """Execution status of a collector."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    FAILED = "FAILED"


@dataclass
class CollectorManifest:
    """Declarative behavior manifest for a collector."""
    name: str
    category: str
    description: str
    requires_root: bool = False
    network_access: bool = False
    writes_system_state: bool = False
    collects_secrets: bool = False
    commands: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "requires_root": self.requires_root,
            "network_access": self.network_access,
            "writes_system_state": self.writes_system_state,
            "collects_secrets": self.collects_secrets,
            "commands": self.commands,
            "outputs": self.outputs,
        }


@dataclass
class CollectorResult:
    """Structured output returned by a collector."""
    collector: str
    status: CollectorStatus
    data: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    message: Optional[str] = None
    raw_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector,
            "status": self.status.value,
            "data": self.data,
            "duration_seconds": round(self.duration_seconds, 4),
            "error": self.error,
            "message": self.message,
            "raw_available": self.raw_available,
        }


class BaseCollector(ABC):
    """Abstract base class for all Linux Server Audit collectors."""

    manifest: CollectorManifest

    def __init__(self) -> None:
        if not hasattr(self, "manifest") or self.manifest is None:
            raise NotImplementedError("Collector must define a manifest")

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def requires_root(self) -> bool:
        return self.manifest.requires_root

    def run(self, executor: Any, context: Optional[Dict[str, Any]] = None) -> CollectorResult:
        """Runs the collector with execution timing and error handling."""
        start_time = time.time()
        try:
            result = self.collect(executor, context or {})
            result.duration_seconds = time.time() - start_time
            return result
        except PermissionError as e:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.PERMISSION_DENIED,
                duration_seconds=time.time() - start_time,
                error=str(e),
                message="Elevated privilege required but unavailable",
            )
        except FileNotFoundError as e:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                duration_seconds=time.time() - start_time,
                error=str(e),
                message=f"Required utility or file not found: {e.filename or str(e)}",
            )
        except Exception as e:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.FAILED,
                duration_seconds=time.time() - start_time,
                error=f"{type(e).__name__}: {str(e)}",
                message=f"Collector failed with unhandled exception: {str(e)}",
            )

    @abstractmethod
    def collect(self, executor: Any, context: Dict[str, Any]) -> CollectorResult:
        """Perform observational collection and return structured data."""
        raise NotImplementedError
