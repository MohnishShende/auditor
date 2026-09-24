"""
Unit tests for core framework components (Executor, Safety, Normalizer, Manifest, Snapshot).
"""

from pathlib import Path
import pytest
from serveraudit.core.executor import CommandExecutor
from serveraudit.core.normalizer import Normalizer
from serveraudit.core.manifest import ManifestGenerator
from serveraudit.core.snapshot import SnapshotManager
from serveraudit.core.collector import CollectorStatus, CollectorResult


def test_executor_safety_blocking():
    """Verify CommandExecutor strictly blocks all modifying/destructive commands."""
    executor = CommandExecutor()

    dangerous_commands = [
        ["rm", "-rf", "/etc"],
        ["mkfs.ext4", "/dev/sda1"],
        ["dd", "if=/dev/zero", "of=/dev/sda"],
        ["systemctl", "stop", "nginx"],
        ["apt", "install", "curl"],
        ["apt-get", "remove", "nginx"],
        ["useradd", "hacker"],
        ["passwd", "root"],
        ["chmod", "777", "/etc/shadow"],
        ["ufw", "disable"],
        ["cryptsetup", "luksFormat", "/dev/sdb"],
    ]

    for cmd in dangerous_commands:
        safe, reason = executor.is_safe_command(cmd)
        assert not safe, f"Failed to block dangerous command: {cmd}"

        res = executor.run(cmd)
        assert not res.success
        assert res.returncode == 126
        assert "Forbidden" in res.stderr or "blocked" in res.stderr.lower()


def test_normalizer_bytes():
    """Test Normalizer.parse_bytes and Normalizer.format_bytes."""
    assert Normalizer.parse_bytes("1024") == 1024
    assert Normalizer.parse_bytes("1K") == 1024
    assert Normalizer.parse_bytes("1M") == 1024**2
    assert Normalizer.parse_bytes("1G") == 1024**3
    assert Normalizer.parse_bytes("1.5GB") == int(1.5 * 1024**3)
    assert Normalizer.parse_bytes("2TB") == 2 * 1024**4

    assert Normalizer.format_bytes(1024) == "1.00 KB"
    assert Normalizer.format_bytes(1024**2 * 500) == "500.00 MB"
    assert Normalizer.format_bytes(1000204886016) == "931.51 GB"


def test_normalizer_uptime():
    """Test Normalizer.format_uptime."""
    assert Normalizer.format_uptime(3665) == "1 hr, 1 min"
    assert Normalizer.format_uptime(90060) == "1 day, 1 hr, 1 min"


def test_snapshot_and_manifest_bundle(tmp_path):
    """Test SnapshotManager bundle creation, checksum calculation, and integrity validation."""
    sm = SnapshotManager(base_directory=tmp_path)

    hostname = "testnode"
    timestamp = "2026-09-24T10:00:00"

    mock_results = {
        "system": CollectorResult("system", CollectorStatus.SUCCESS, duration_seconds=0.1),
        "storage": CollectorResult("storage", CollectorStatus.PARTIAL, error="Non-critical warning"),
    }

    manifest = ManifestGenerator.generate(
        hostname=hostname,
        profile="private",
        duration_seconds=1.5,
        results=mock_results,
        privileges_available=True,
    )

    snap_dir = sm.create_snapshot_dir(hostname, timestamp)
    audit_json = {"metadata": {"hostname": hostname, "timestamp": timestamp}}
    audit_md = "# Test Report"
    audit_html = "<html><body>Report</body></html>"

    checksums = sm.save_bundle(
        snapshot_dir=snap_dir,
        audit_json=audit_json,
        audit_md=audit_md,
        manifest_json=manifest,
        audit_html=audit_html,
    )

    assert "audit.json" in checksums
    assert "audit.md" in checksums
    assert "manifest.json" in checksums
    assert "audit.html" in checksums
    assert (snap_dir / "checksums.sha256").exists()

    # Verify integrity passes
    valid, issues = sm.verify_integrity(snap_dir)
    assert valid, f"Integrity check failed: {issues}"

    # Corrupt audit.md and test that integrity check detects tamper
    with open(snap_dir / "audit.md", "a") as f:
        f.write("\nTampered content")

    valid_after_tamper, issues_after = sm.verify_integrity(snap_dir)
    assert not valid_after_tamper
    assert any("Checksum mismatch" in i for i in issues_after)
