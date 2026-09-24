"""
Collector registry and discovery for Linux Server Audit.
"""

from __future__ import annotations
from typing import Dict, List, Type

from ..core.collector import BaseCollector

COLLECTOR_REGISTRY: Dict[str, Type[BaseCollector]] = {}


def register_collector(cls: Type[BaseCollector]) -> Type[BaseCollector]:
    """Decorator to register a collector class."""
    if hasattr(cls, "manifest") and cls.manifest is not None:
        COLLECTOR_REGISTRY[cls.manifest.name] = cls
    return cls


def get_all_collectors() -> Dict[str, BaseCollector]:
    """Instantiate and return all registered collectors."""
    # Ensure all collector modules are imported
    from . import (
        system,
        hardware,
        firmware,
        cpu,
        memory,
        pci,
        usb,
        storage,
        smart,
        filesystems,
        fstab,
        lvm,
        raid,
        zfs,
        btrfs,
        encryption,
        network,
        routes,
        dns,
        ports,
        active_net,
        firewall,
        fail2ban,
        ssh,
        users,
        security,
        systemd,
        processes,
        runtime_health,
        packages,
        docker,
        caddy,
        tls,
        scheduled,
        backups,
        logs,
        thermal,
        power,
        boot,
        time as time_sync,
        sharing,
        permissions,
        applications,
    )
    return {name: cls() for name, cls in COLLECTOR_REGISTRY.items()}
