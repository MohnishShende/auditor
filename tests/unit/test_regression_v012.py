"""
Regression tests for v0.1.2 Docker container inventory & executor safety denylist fixes.
"""

import json
import pytest
from unittest.mock import MagicMock

from serveraudit.core.collector import CollectorStatus
from serveraudit.core.executor import CommandExecutor, CommandOutput
from serveraudit.collectors.docker import DockerCollector, parse_docker_labels, parse_docker_ports, parse_docker_mounts


def test_executor_is_safe_command_does_not_block_format():
    """Verify that --format or other flags containing 'rm' are NOT blocked as forbidden."""
    executor = CommandExecutor()

    # Commands with --format should be allowed
    safe_cmds = [
        ["docker", "version", "--format", "{{json .}}"],
        ["docker", "info", "--format", "{{json .}}"],
        ["docker", "ps", "-a", "--format", "{{json .}}"],
        ["docker", "images", "--format", "{{json .}}"],
        ["docker", "volume", "ls", "--format", "{{json .}}"],
        ["docker", "network", "ls", "--format", "{{json .}}"],
        ["lscpu", "-J"],
        ["systemctl", "status", "docker"],
        ["ufw", "status", "numbered"],
    ]

    for cmd in safe_cmds:
        safe, reason = executor.is_safe_command(cmd)
        assert safe, f"Command {cmd} should be safe but was blocked: {reason}"

    # Dangerous commands must still be blocked
    dangerous_cmds = [
        ["rm", "-rf", "/tmp/test"],
        ["docker", "rm", "mycontainer"],
        ["docker", "rmi", "myimage"],
        ["docker", "run", "-d", "nginx"],
        ["docker", "stop", "mycontainer"],
        ["systemctl", "restart", "nginx"],
        ["apt-get", "install", "htop"],
        ["ufw", "enable"],
    ]

    for cmd in dangerous_cmds:
        safe, reason = executor.is_safe_command(cmd)
        assert not safe, f"Dangerous command {cmd} should be blocked but was allowed!"


def test_docker_ndjson_parsing_fixtures():
    """Verify Docker collector parses real newline-delimited JSON from Docker 29.8.1."""
    executor = MagicMock()
    executor.which.return_value = "/usr/bin/docker"
    executor.privileges = MagicMock()
    executor.privileges.can_elevate = True

    # Realistic sanitized NDJSON payload (Docker 29.8.1 shape)
    ndjson_output = "\n".join([
        json.dumps({
            "Command": '"docker-entrypoint.sh"',
            "CreatedAt": "2026-09-23 05:48:41 +0000 UTC",
            "HealthStatus": "healthy",
            "ID": "c63a358fcf14",
            "Image": "postgres:16-alpine",
            "Labels": "com.docker.compose.project=app-db,com.docker.compose.service=db",
            "LocalVolumes": "0",
            "Mounts": "/srv/data/db",
            "Names": "app-db",
            "Networks": "app-net",
            "Platform": {"architecture": "amd64", "os": "linux"},
            "Ports": "5432/tcp",
            "RunningFor": "31 hours ago",
            "Size": "20.5kB (virtual 303MB)",
            "State": "running",
            "Status": "Up 3 hours (healthy)"
        }),
        json.dumps({
            "Command": '"/usr/bin/caddy run"',
            "CreatedAt": "2026-09-23 05:48:41 +0000 UTC",
            "HealthStatus": "none",
            "ID": "843ac8d12b5f",
            "Image": "caddy:2-alpine",
            "Labels": "com.docker.compose.project=gateway,com.docker.compose.service=caddy",
            "LocalVolumes": "0",
            "Mounts": "/srv/caddy/data,/srv/caddy/config",
            "Names": "caddy-proxy",
            "Networks": "app-net",
            "Platform": {"architecture": "amd64", "os": "linux"},
            "Ports": "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 443/udp",
            "RunningFor": "31 hours ago",
            "Size": "10.2kB (virtual 50MB)",
            "State": "running",
            "Status": "Up 3 hours"
        }),
    ])

    def mock_run(cmd, use_sudo=False, **kwargs):
        cmd_str = " ".join(cmd)
        if "docker version" in cmd_str:
            return CommandOutput(
                command=cmd,
                stdout=json.dumps({"Server": {"Version": "29.8.1", "ApiVersion": "1.56"}}),
                stderr="",
                returncode=0,
                duration_seconds=0.01,
                success=True,
                used_sudo=False,
            )
        elif "docker info" in cmd_str:
            return CommandOutput(
                command=cmd,
                stdout=json.dumps({"ServerVersion": "29.8.1", "Driver": "overlay2"}),
                stderr="",
                returncode=0,
                duration_seconds=0.01,
                success=True,
                used_sudo=False,
            )
        elif "docker ps" in cmd_str and "{{json .}}" in cmd_str:
            return CommandOutput(
                command=cmd,
                stdout=ndjson_output,
                stderr="",
                returncode=0,
                duration_seconds=0.01,
                success=True,
                used_sudo=False,
            )
        elif "docker inspect" in cmd_str:
            return CommandOutput(command=cmd, stdout="", stderr="", returncode=1, duration_seconds=0.01, success=False, used_sudo=False)
        return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)

    executor.run.side_effect = mock_run

    collector = DockerCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["engine"]["active"] is True
    assert res.data["engine"]["server_version"] == "29.8.1"
    assert len(res.data["containers"]) == 2
    assert res.data["engine"]["containers_running"] == 2

    c0 = res.data["containers"][0]
    assert c0["name"] == "app-db"
    assert c0["image"] == "postgres:16-alpine"
    assert c0["compose_project"] == "app-db"
    assert c0["compose_service"] == "db"
    assert len(c0["ports"]) == 1
    assert c0["ports"][0]["container_port"] == "5432/tcp"

    c1 = res.data["containers"][1]
    assert c1["name"] == "caddy-proxy"
    assert c1["image"] == "caddy:2-alpine"
    assert len(c1["ports"]) == 3
    assert c1["ports"][0]["host_port"] == "80"
