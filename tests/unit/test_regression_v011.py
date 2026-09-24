"""
Regression tests for v0.1.1 bug fixes:
- Bug 1: CLI wrapper symlink resolution
- Bug 2: CPU collector resilience & Linux output variations
- Bug 3: Docker collector availability, status differentiation, & Docker 29.x output
- Bug 4: CLI module import without runpy RuntimeWarning
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from unittest.mock import MagicMock

from serveraudit.core.collector import CollectorStatus
from serveraudit.core.executor import CommandExecutor, CommandOutput
from serveraudit.core.privileges import PrivilegeManager
from serveraudit.collectors.cpu import CpuCollector
from serveraudit.collectors.docker import DockerCollector


def test_bug4_no_runpy_runtime_warning():
    """Verify that python -m serveraudit.cli.main executes without RuntimeWarning."""
    env = os.environ.copy()
    src_dir = str(Path(__file__).resolve().parent.parent.parent / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [sys.executable, "-W", "error", "-m", "serveraudit.cli.main", "--version"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    assert "serveraudit" in result.stdout
    assert "RuntimeWarning" not in result.stderr


def test_bug2_cpu_collector_tolerant_parsing():
    """Verify CPU collector handles real Linux /proc/cpuinfo without KeyError: 'model_name'."""
    executor = MagicMock()
    executor.which.return_value = None

    # Realistic Ubuntu /proc/cpuinfo snippet with 'model name'
    real_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 94
model name	: Intel(R) Core(TM) i5-6500TE CPU @ 2.30GHz
stepping	: 3
microcode	: 0xf0
cpu MHz		: 2300.000
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 4
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 94
model name	: Intel(R) Core(TM) i5-6500TE CPU @ 2.30GHz
stepping	: 3
microcode	: 0xf0
cpu MHz		: 2300.000
cache size	: 6144 KB
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 4
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities
"""
    executor.read_file.side_effect = lambda p: real_cpuinfo if str(p) == "/proc/cpuinfo" else None

    collector = CpuCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["model_name"] == "Intel(R) Core(TM) i5-6500TE CPU @ 2.30GHz"
    assert res.data["vendor_id"] == "GenuineIntel"
    assert res.data["logical_cpus"] == 2
    assert res.data["physical_cores"] == 2
    assert res.data["capabilities"]["avx2"] is True


def test_bug2_cpu_collector_missing_model_partial():
    """Verify CPU collector returns PARTIAL gracefully if model is missing without crashing."""
    executor = MagicMock()
    executor.which.return_value = None

    # Incomplete cpuinfo missing model name
    incomplete_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
physical id	: 0
core id		: 0
"""
    executor.read_file.side_effect = lambda p: incomplete_cpuinfo if str(p) == "/proc/cpuinfo" else None

    collector = CpuCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.PARTIAL
    assert res.data["model_name"] is None
    assert res.data["logical_cpus"] == 1


def test_bug3_docker_missing_cli():
    """Verify Docker collector reports SKIPPED when docker binary is missing."""
    executor = MagicMock()
    executor.which.return_value = None

    collector = DockerCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.SKIPPED
    assert "not found in PATH" in res.message


def test_bug3_docker_daemon_stopped():
    """Verify Docker collector distinguishes stopped daemon from permission denied."""
    executor = MagicMock()
    executor.which.return_value = "/usr/bin/docker"
    executor.privileges = MagicMock()
    executor.privileges.can_elevate = False

    executor.run.return_value = CommandOutput(
        command=["docker", "version", "--format", "{{json .}}"],
        stdout="",
        stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        returncode=1,
        duration_seconds=0.01,
        success=False,
        used_sudo=False,
    )

    collector = DockerCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.SKIPPED
    assert "not running" in res.message


def test_bug3_docker_permission_denied():
    """Verify Docker collector distinguishes permission denied on socket."""
    executor = MagicMock()
    executor.which.return_value = "/usr/bin/docker"
    executor.privileges = MagicMock()
    executor.privileges.can_elevate = False

    executor.run.return_value = CommandOutput(
        command=["docker", "version", "--format", "{{json .}}"],
        stdout="",
        stderr="permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
        returncode=1,
        duration_seconds=0.01,
        success=False,
        used_sudo=False,
    )

    collector = DockerCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.PERMISSION_DENIED
    assert "Permission denied" in res.message


def test_bug3_docker_29_operational():
    """Verify Docker collector parses Docker 29.8.1 / API 1.56 output with 9 containers."""
    executor = MagicMock()
    executor.which.return_value = "/usr/bin/docker"
    executor.privileges = MagicMock()
    executor.privileges.can_elevate = True

    # Mock docker version JSON
    docker_version_json = json.dumps({
        "Client": {"Version": "29.8.1", "ApiVersion": "1.56"},
        "Server": {"Version": "29.8.1", "ApiVersion": "1.56"}
    })

    # Mock docker ps IDs
    mock_ps_ids = "c1 c2 c3 c4 c5 c6 c7 c8 c9"

    # Mock docker inspect JSON
    mock_inspect = [
        {"Id": f"cid_{i:02d}abcdef123456", "Name": f"/container_{name}", "State": {"Status": "running"}, "Config": {"Image": f"{name}:latest", "Env": ["PASSWORD=secret", "PORT=8080"]}, "Mounts": [], "NetworkSettings": {"Ports": {}}}
        for i, name in enumerate(["paperless-web", "caddy", "paperless-redis", "paperless-db", "searxng", "searxng-valkey", "homarr", "jellyfin", "pihole"], 1)
    ]

    def mock_run(cmd, use_sudo=False, **kwargs):
        cmd_str = " ".join(cmd)
        if "docker version" in cmd_str:
            return CommandOutput(command=cmd, stdout=docker_version_json, stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker info" in cmd_str:
            return CommandOutput(command=cmd, stdout=json.dumps({"ServerVersion": "29.8.1", "Driver": "overlay2", "ContainersRunning": 9, "Containers": 9}), stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker ps" in cmd_str:
            return CommandOutput(command=cmd, stdout=mock_ps_ids, stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker inspect" in cmd_str:
            return CommandOutput(command=cmd, stdout=json.dumps(mock_inspect), stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker images" in cmd_str:
            return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker volume" in cmd_str:
            return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker network" in cmd_str:
            return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        elif "docker compose" in cmd_str:
            return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)
        return CommandOutput(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.01, success=True, used_sudo=False)

    executor.run.side_effect = mock_run

    collector = DockerCollector()
    res = collector.collect(executor, {})

    assert res.status == CollectorStatus.SUCCESS
    assert res.data["engine"]["active"] is True
    assert res.data["engine"]["server_version"] == "29.8.1"
    assert len(res.data["containers"]) == 9
    assert res.data["containers"][0]["name"] == "container_paperless-web"
    assert res.data["containers"][0]["environment_keys"] == ["PASSWORD", "PORT"]


def test_bug1_wrapper_script_structure():
    """Verify that bin/serveraudit contains bash symlink resolution loop."""
    wrapper_path = Path(__file__).resolve().parent.parent.parent / "bin" / "serveraudit"
    assert wrapper_path.exists(), "bin/serveraudit wrapper must exist"

    content = wrapper_path.read_text(encoding="utf-8")
    assert "while [ -L " in content
    assert "readlink " in content
    assert 'SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")/.." && pwd)"' in content
