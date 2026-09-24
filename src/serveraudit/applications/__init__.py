"""
Application discovery plugins for Linux Server Audit.
Detects common self-hosted applications and services running natively or via Docker.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class DiscoveredApplication:
    name: str
    category: str
    version: Optional[str] = None
    deployment_type: str = "native"  # "docker", "native", "systemd"
    container_name: Optional[str] = None
    ports: List[int] = None
    storage_paths: List[str] = None
    status: str = "running"
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "deployment_type": self.deployment_type,
            "container_name": self.container_name,
            "ports": self.ports or [],
            "storage_paths": self.storage_paths or [],
            "status": self.status,
            "details": self.details or {},
        }


# Signatures for container and native service detection
KNOWN_APPS = [
    {
        "name": "Jellyfin",
        "category": "Media",
        "container_match": r"jellyfin",
        "image_match": r"jellyfin/jellyfin",
        "default_port": 8096,
    },
    {
        "name": "Paperless-ngx",
        "category": "Document Management",
        "container_match": r"paperless(-ngx|-webserver)?",
        "image_match": r"ghcr\.io/paperless-ngx/paperless-ngx",
        "default_port": 8000,
    },
    {
        "name": "Pi-hole",
        "category": "DNS & Ad-blocking",
        "container_match": r"pihole",
        "image_match": r"pihole/pihole",
        "default_port": 53,
    },
    {
        "name": "qBittorrent",
        "category": "Downloads",
        "container_match": r"qbittorrent",
        "image_match": r"linuxserver/qbittorrent",
        "default_port": 8080,
    },
    {
        "name": "Sonarr",
        "category": "Media Management",
        "container_match": r"sonarr",
        "image_match": r"linuxserver/sonarr",
        "default_port": 8989,
    },
    {
        "name": "Radarr",
        "category": "Media Management",
        "container_match": r"radarr",
        "image_match": r"linuxserver/radarr",
        "default_port": 7878,
    },
    {
        "name": "Prowlarr",
        "category": "Media Management",
        "container_match": r"prowlarr",
        "image_match": r"linuxserver/prowlarr",
        "default_port": 9696,
    },
    {
        "name": "Bazarr",
        "category": "Media Management",
        "container_match": r"bazarr",
        "image_match": r"linuxserver/bazarr",
        "default_port": 6767,
    },
    {
        "name": "Kavita",
        "category": "Reader",
        "container_match": r"kavita",
        "image_match": r"kavitareader/kavita",
        "default_port": 5000,
    },
    {
        "name": "SearXNG",
        "category": "Search",
        "container_match": r"searxng",
        "image_match": r"searxng/searxng",
        "default_port": 8080,
    },
    {
        "name": "PostgreSQL",
        "category": "Database",
        "container_match": r"(postgres|psql|paperless-db)",
        "image_match": r"postgres",
        "default_port": 5432,
    },
    {
        "name": "Redis / Valkey",
        "category": "Database (In-Memory)",
        "container_match": r"(redis|valkey|paperless-redis)",
        "image_match": r"(redis|valkey)",
        "default_port": 6379,
    },
    {
        "name": "MariaDB / MySQL",
        "category": "Database",
        "container_match": r"(mariadb|mysql)",
        "image_match": r"(mariadb|mysql)",
        "default_port": 3306,
    },
]
