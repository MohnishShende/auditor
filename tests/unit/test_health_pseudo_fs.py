"""
Kernel pseudo-filesystems (efivarfs, sysfs, cgroup, ...) report a tiny fixed capacity that is
always nearly full; they must not produce "Disk Space Critical" findings. Real filesystems,
including tmpfs, must still be checked.
"""

import pytest

from serveraudit.analysis.health import evaluate_health


def _findings(fstype, pct, target="/x"):
    data = {"filesystems": {"mounts": [{"target": target, "fstype": fstype, "percent_used": pct,
                                        "available_formatted": "6.89 KB"}]}}
    return [f for f in evaluate_health(data) if f["subsystem"] == "Filesystems"]


def test_efivarfs_at_95_percent_is_not_a_finding():
    # Real entry from a host: /sys/firmware/efi/efivars, 95% used, 6.89 KB available.
    assert _findings("efivarfs", 95.0, "/sys/firmware/efi/efivars") == []


@pytest.mark.parametrize("fstype", ["sysfs", "proc", "cgroup2", "securityfs", "debugfs", "tracefs", "pstore", "bpf", "configfs", "fusectl"])
def test_other_kernel_pseudo_filesystems_are_ignored(fstype):
    assert _findings(fstype, 100.0) == []


@pytest.mark.parametrize("fstype,pct,sev", [("ext4", 96, "CRITICAL"), ("xfs", 90, "WARNING"), ("tmpfs", 97, "CRITICAL"),
                                            ("overlay", 99, "CRITICAL"), (None, 96, "CRITICAL")])
def test_real_and_memory_filesystems_are_still_checked(fstype, pct, sev):
    f = _findings(fstype, pct)
    assert len(f) == 1 and f[0]["severity"] == sev
