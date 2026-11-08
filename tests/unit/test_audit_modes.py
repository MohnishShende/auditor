"""
Focused test suite for audit modes (USER / SUDO), privilege enforcement,
and hard invariants.
"""

from __future__ import annotations
import os
import subprocess
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile
import sys

from serveraudit.core.collector import (
    BaseCollector,
    CollectorManifest,
    CollectorResult,
    CollectorStatus,
    PrivilegeLevel,
)
from serveraudit.core.executor import CommandExecutor, CommandOutput
from serveraudit.core.privileges import AuditMode, PrivilegeManager
from serveraudit.cli.audit import AuditOrchestrator
from serveraudit.collectors.ports import PortsCollector
from serveraudit.collectors.users import UsersCollector
from serveraudit.collectors.docker import DockerCollector
from serveraudit.collectors.hardware import HardwareCollector
from serveraudit.collectors.ssh import SshCollector
from serveraudit.collectors.logs import LogsCollector
from serveraudit.collectors.scheduled import ScheduledCollector


def test_user_mode_spawns_zero_sudo_subprocesses():
    """
    1. USER mode spawns ZERO sudo processes.
    Verify globally around subprocess execution, including when sudo exists and
    cached credentials would otherwise succeed.
    """
    spawned_commands = []

    def mock_subprocess_run(cmd, *args, **kwargs):
        spawned_commands.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        # 1. PrivilegeManager construction in USER mode
        pm = PrivilegeManager(mode=AuditMode.USER)
        assert pm.has_sudo is False
        assert pm.validate_sudo() is False

        # 2. CommandExecutor in USER mode
        executor = CommandExecutor(privilege_manager=pm, mode=AuditMode.USER)

        # Normal observational run
        executor.run(["uname", "-a"])
        # File read
        executor.read_file("/etc/os-release")

        # Verify no command spawned contained sudo or was sudo
        for sc in spawned_commands:
            cmd_list = sc if isinstance(sc, list) else sc.split()
            assert cmd_list[0] != "sudo", f"Sudo was spawned in USER mode: {cmd_list}"
            assert not any("sudo" in arg for arg in cmd_list[:2]), f"Unexpected sudo invocation: {cmd_list}"


def test_user_mode_never_calls_sudo_checks():
    """
    2. USER mode never calls sudo -n true, sudo -v, or sudo -n <cmd>.
    """
    called_cmds = []

    def tracking_run(cmd, *args, **kwargs):
        called_cmds.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=tracking_run):
        pm = PrivilegeManager(mode=AuditMode.USER)
        _ = pm.has_sudo
        _ = pm.can_elevate
        pm.validate_sudo()

        executor = CommandExecutor(pm, mode=AuditMode.USER)
        executor.run(["ls", "/tmp"], use_sudo=False)

    for cmd in called_cmds:
        assert "sudo" not in cmd, f"Forbidden sudo call in USER mode: {cmd}"


def test_user_mode_euid_zero_rejected():
    """
    3. USER mode with EUID 0 is rejected before collection begins.
    """
    from serveraudit.cli.main import main

    with patch("sys.argv", ["serveraudit", "audit", "--mode", "user"]):
        with patch("os.geteuid", return_value=0):
            with patch("sys.stderr.write") as mock_err:
                ret = main()
                assert ret == 1
                mock_err.assert_called()
                err_text = "".join(call[0][0] for call in mock_err.call_args_list)
                assert "cannot be run as root" in err_text


def test_executor_rejects_use_sudo_in_user_mode():
    """
    4. A collector mistakenly calling executor.run(..., use_sudo=True) in USER mode cannot spawn sudo.
    """
    pm = PrivilegeManager(mode=AuditMode.USER)
    executor = CommandExecutor(pm, mode=AuditMode.USER)

    with patch("subprocess.run") as mock_run:
        out = executor.run(["cat", "/etc/shadow"], use_sudo=True)
        assert not mock_run.called, "subprocess.run should NOT be called"
        assert out.success is False
        assert out.returncode == 126
        assert "PrivilegePolicyViolation" in out.stderr
        assert out.used_sudo is False


def test_executor_rejects_argv_sudo_in_user_mode():
    """
    5. An explicit argv command beginning with sudo is blocked in USER mode.
    """
    pm = PrivilegeManager(mode=AuditMode.USER)
    executor = CommandExecutor(pm, mode=AuditMode.USER)

    with patch("subprocess.run") as mock_run:
        out = executor.run(["sudo", "whoami"])
        assert not mock_run.called
        assert out.success is False
        assert out.returncode == 126
        assert "Direct invocation of sudo is forbidden" in out.stderr


def test_executor_read_file_zero_sudo_in_user_mode():
    """
    6. File-reading helper also respects zero sudo invariant in USER mode.
    """
    pm = PrivilegeManager(mode=AuditMode.USER)
    executor = CommandExecutor(pm, mode=AuditMode.USER)

    with patch("subprocess.run") as mock_run:
        # Request read with use_sudo=True
        content = executor.read_file("/etc/nonexistent_restricted_file", use_sudo=True)
        assert not mock_run.called
        assert content is None


def test_required_collectors_skipped_in_user_mode():
    """
    7. REQUIRED collectors are SKIPPED in USER mode with skip_reason='requires_privilege'.
    """
    pm = PrivilegeManager(mode=AuditMode.USER)
    executor = CommandExecutor(pm, mode=AuditMode.USER)

    with tempfile.TemporaryDirectory() as tmp_dir:
        orchestrator = AuditOrchestrator(
            mode=AuditMode.USER,
            output_dir=tmp_dir,
            formats=["json"],
            quiet=True,
            privilege_manager=pm,
            executor=executor,
        )

        def fake_run(cmd, *args, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run) as mock_sub:
            snap_dir = orchestrator.run_audit()
            # Verify no subprocess ran sudo
            for call in mock_sub.call_args_list:
                args = call[0][0]
                assert "sudo" not in args

        import json
        with open(snap_dir / "audit.json", "r", encoding="utf-8") as f:
            audit_data = json.load(f)

        assert audit_data["metadata"]["audit_mode"] == "user"
        collectors_res = audit_data["collectors"]

        required_collectors = ["encryption", "fail2ban", "firewall", "lvm", "smart"]
        for rc in required_collectors:
            assert rc in collectors_res, f"{rc} should be in collectors output"
            assert collectors_res[rc]["status"] == "SKIPPED", f"{rc} status was {collectors_res[rc]['status']}"
            assert collectors_res[rc].get("skip_reason") == "requires_privilege", f"{rc} skip_reason wrong"


def test_optional_collectors_unprivileged_probes():
    """
    8. OPTIONAL collectors execute actual unprivileged probes instead of requesting sudo.
       Tests: ports, users, docker, hardware, ssh, logs.
    """
    pm = PrivilegeManager(mode=AuditMode.USER)
    executor = CommandExecutor(pm, mode=AuditMode.USER)

    # 1. Ports: ss -tuln
    ports_col = PortsCollector()
    with patch.object(executor, "run") as mock_run:
        mock_run.return_value = CommandOutput(
            command=["ss", "-tuln"],
            stdout="Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
            stderr="",
            returncode=0,
            duration_seconds=0.01,
            success=True,
            used_sudo=False,
        )
        res = ports_col.collect(executor, {})
        assert mock_run.called
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["ss", "-tuln"], f"Expected ss -tuln, got {called_cmd}"
        assert mock_run.call_args[1].get("use_sudo") is False
        assert len(res.data["listening_ports"]) == 1
        assert res.data["listening_ports"][0]["port"] == 22
        assert res.data["listening_ports"][0]["process"] is None

    # 2. Users: skips /etc/shadow
    users_col = UsersCollector()
    with patch.object(executor, "read_file") as mock_rf:
        mock_rf.side_effect = lambda path, **kw: {
            "/etc/group": "sudo:x:27:alice\nusers:x:100:bob",
            "/etc/passwd": "alice:x:1000:1000::/home/alice:/bin/bash\nroot:x:0:0::/root:/bin/bash",
        }.get(str(path))
        res = users_col.collect(executor, {})
        # Verify /etc/shadow was NOT read
        read_paths = [str(call[0][0]) for call in mock_rf.call_args_list]
        assert "/etc/shadow" not in read_paths
        assert len(res.data["users"]) == 2
        for u in res.data["users"]:
            assert u["password_status"] == "UNKNOWN"

    # 3. Docker: unprivileged only, never falls back to sudo in USER mode
    docker_col = DockerCollector()
    with patch.object(executor, "which", return_value="/usr/bin/docker"):
        with patch.object(executor, "run") as mock_run:
            mock_run.return_value = CommandOutput(
                command=["docker", "version", "--format", "{{json .}}"],
                stdout="",
                stderr="Got permission denied while trying to connect to the Docker daemon socket",
                returncode=1,
                duration_seconds=0.01,
                success=False,
                used_sudo=False,
            )
            res = docker_col.collect(executor, {})
            # Only one call, never tried with use_sudo=True
            assert mock_run.call_count == 1
            assert mock_run.call_args[1].get("use_sudo") is False
            assert res.status == CollectorStatus.PERMISSION_DENIED

    # 4. Hardware: skips dmidecode
    hw_col = HardwareCollector()
    with patch.object(executor, "which", return_value="/usr/sbin/dmidecode"):
        with patch.object(executor, "run") as mock_run:
            with patch.object(executor, "read_file", return_value=None):
                res = hw_col.collect(executor, {})
                assert not mock_run.called

    # 5. SSH: skips sshd -T
    ssh_col = SshCollector()
    with patch.object(executor, "which", return_value="/usr/sbin/sshd"):
        with patch.object(executor, "run") as mock_run:
            mock_run.return_value = CommandOutput(
                command=["ssh", "-V"],
                stdout="OpenSSH_9.6p1",
                stderr="",
                returncode=0,
                duration_seconds=0.01,
                success=True,
                used_sudo=False,
            )
            res = ssh_col.collect(executor, {})
            called_cmds = [call[0][0] for call in mock_run.call_args_list]
            assert ["sshd", "-T"] not in called_cmds

    # 6. Logs: runs journalctl without sudo in USER mode
    logs_col = LogsCollector()
    with patch.object(executor, "which", return_value="/usr/bin/journalctl"):
        with patch.object(executor, "run") as mock_run:
            mock_run.return_value = CommandOutput(
                command=["journalctl", "--disk-usage"],
                stdout="Archived and active journals take up 120.0M in the file system.",
                stderr="",
                returncode=0,
                duration_seconds=0.01,
                success=True,
                used_sudo=False,
            )
            res = logs_col.collect(executor, {})
            for call in mock_run.call_args_list:
                assert call[1].get("use_sudo") is False


def test_sudo_mode_validation_and_lifecycle():
    """
    10. SUDO mode:
    - executes sudo -v once for non-root users
    - uses sudo -n for privileged commands after validation
    - never prompts again mid-audit
    - handles expired credentials deterministically
    """
    # 1. Non-root validation
    with patch("os.geteuid", return_value=1000):
        with patch("shutil.which", return_value="/usr/bin/sudo"):
            with patch("subprocess.run") as mock_sub:
                mock_sub.return_value = subprocess.CompletedProcess(args=["sudo", "-v"], returncode=0)
                pm = PrivilegeManager(mode=AuditMode.SUDO)
                valid = pm.validate_sudo()
                assert valid is True
                assert pm.has_sudo is True
                mock_sub.assert_called_once_with(["sudo", "-v"], check=False)

    # 2. Privileged commands use sudo -n
    executor = CommandExecutor(pm, mode=AuditMode.SUDO)
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=["sudo", "-n", "dmsetup", "ls"],
            returncode=0,
            stdout="crypt_root\n",
            stderr="",
        )
        out = executor.run(["dmsetup", "ls"], use_sudo=True)
        assert out.success is True
        assert out.used_sudo is True
        assert mock_sub.call_args[0][0] == ["sudo", "-n", "dmsetup", "ls"]

    # 3. Deterministic expiry handling
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=["sudo", "-n", "pvs"],
            returncode=1,
            stdout="",
            stderr="sudo: a password is required",
        )
        out = executor.run(["pvs"], use_sudo=True)
        assert out.success is False
        assert out.returncode == 1
        assert "sudo: a password is required" in out.stderr


def test_root_sudo_mode_no_unnecessary_sudo():
    """
    11. Root SUDO mode does not invoke sudo unnecessarily.
    """
    with patch("os.geteuid", return_value=0):
        pm = PrivilegeManager(mode=AuditMode.SUDO)
        assert pm.is_root is True
        assert pm.can_elevate is True

        with patch("subprocess.run") as mock_sub:
            valid = pm.validate_sudo()
            assert valid is True
            # No sudo -v needed for root
            assert not mock_sub.called

        executor = CommandExecutor(pm, mode=AuditMode.SUDO)
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = subprocess.CompletedProcess(args=["dmsetup", "ls"], returncode=0, stdout="", stderr="")
            out = executor.run(["dmsetup", "ls"], use_sudo=True)
            assert out.success is True
            assert out.used_sudo is False
            assert mock_sub.call_args[0][0] == ["dmsetup", "ls"]
