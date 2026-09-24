"""
Unit tests for collector parsing and graceful error handling.
"""

from unittest.mock import MagicMock
import pytest
from serveraudit.collectors.system import SystemCollector
from serveraudit.collectors.cpu import CpuCollector
from serveraudit.collectors.memory import MemoryCollector
from serveraudit.collectors.fstab import FstabCollector
from serveraudit.collectors.ports import PortsCollector
from serveraudit.collectors.ssh import SshCollector
from serveraudit.collectors.caddy import CaddyCollector
from serveraudit.collectors.applications import ApplicationsCollector
from serveraudit.core.collector import CollectorStatus
from serveraudit.core.executor import CommandExecutor, CommandOutput


def test_system_collector_parsing():
    """Test SystemCollector with mocked /etc/os-release and /proc/uptime."""
    executor = MagicMock(spec=CommandExecutor)
    executor.read_file.side_effect = lambda path, **kwargs: {
        "/etc/os-release": 'NAME="Ubuntu"\nVERSION="26.04.1 LTS"\nID=ubuntu\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 26.04.1 LTS"',
        "/proc/uptime": "123456.78 98765.43",
        "/proc/cmdline": "BOOT_IMAGE=/vmlinuz-7.0.0 root=UUID=1234 ro quiet splash",
        "/etc/machine-id": "abcdef0123456789",
    }.get(str(path))

    executor.run.return_value = CommandOutput(
        command=["systemd-detect-virt"],
        stdout="none",
        stderr="",
        returncode=0,
        duration_seconds=0.01,
        success=True,
        used_sudo=False,
    )

    collector = SystemCollector()
    res = collector.run(executor)

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["os"]["name"] == "Ubuntu"
    assert res.data["os"]["version"] == "26.04.1 LTS"
    assert res.data["uptime_seconds"] == 123456.78
    assert res.data["machine_id"] == "abcdef0123456789"


def test_fstab_collector_warnings():
    """Test FstabCollector identifies duplicate mountpoints and parses options."""
    executor = MagicMock(spec=CommandExecutor)
    fstab_mock = """# /etc/fstab
UUID=1111-2222 / ext4 defaults,noatime 0 1
UUID=3333-4444 /boot ext4 defaults 0 2
UUID=5555-6666 /srv/data ext4 defaults 0 2
UUID=7777-8888 /srv/data xfs defaults 0 2
"""
    executor.read_file.return_value = fstab_mock

    collector = FstabCollector()
    res = collector.run(executor)

    assert res.status == CollectorStatus.SUCCESS
    assert len(res.data["entries"]) == 4
    assert any("Duplicate mountpoint" in w and "/srv/data" in w for w in res.data["warnings"])


def test_caddy_collector_parsing():
    """Test CaddyCollector extracts reverse proxy upstreams and site hostnames."""
    executor = MagicMock(spec=CommandExecutor)
    executor.which.return_value = "/usr/bin/caddy"
    executor.read_file.return_value = """
paperless.local:443 {
    reverse_proxy 127.0.0.1:8000
    tls internal
}

jellyfin.local {
    reverse_proxy 192.168.1.50:8096
}
"""
    executor.run.return_value = CommandOutput(
        command=["caddy", "version"],
        stdout="v2.8.4 h1:abc123",
        stderr="",
        returncode=0,
        duration_seconds=0.01,
        success=True,
        used_sudo=False,
    )

    collector = CaddyCollector()
    res = collector.run(executor)

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["version"] == "v2.8.4 h1:abc123"
    assert len(res.data["sites"]) == 2
    assert len(res.data["reverse_proxies"]) == 2
    assert res.data["reverse_proxies"][0]["upstream"] == "127.0.0.1:8000"


def test_applications_collector_correlation():
    """Test ApplicationsCollector matches Docker containers against application signatures."""
    executor = MagicMock(spec=CommandExecutor)
    collector = ApplicationsCollector()

    context = {
        "docker": {
            "containers": [
                {
                    "name": "paperless-webserver",
                    "image": "ghcr.io/paperless-ngx/paperless-ngx:latest",
                    "state": "running",
                    "ports": [{"container_port": "8000/tcp", "host_port": "8000"}],
                    "mounts": [{"type": "bind", "source": "/srv/appdata/paperless/data", "destination": "/usr/src/paperless/data"}],
                    "compose_project": "paperless",
                },
                {
                    "name": "jellyfin-media",
                    "image": "jellyfin/jellyfin:latest",
                    "state": "running",
                    "ports": [{"container_port": "8096/tcp", "host_port": "8096"}],
                    "mounts": [{"type": "bind", "source": "/srv/media", "destination": "/media"}],
                    "compose_project": "media",
                },
            ]
        },
        "ports": {"listening_ports": []},
    }

    res = collector.run(executor, context=context)

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["apps_count"] == 2
    app_names = [a["name"] for a in res.data["applications"]]
    assert "Paperless-ngx" in app_names
    assert "Jellyfin" in app_names
