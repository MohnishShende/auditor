"""
User-mode (unprivileged) audits must say what they could NOT collect, instead of
reporting root-only data as "unknown" / "Configured" (an AI agent reading a pasted
report cannot tell "could not read" from "unset").
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from serveraudit.collectors.ssh import SshCollector
from serveraudit.core.collector import CollectorStatus
from serveraudit.core.executor import CommandExecutor, CommandOutput
from serveraudit.renderers.markdown import MarkdownRenderer

NOT_COLLECTED = "not collected"


def _executor(mode: str, can_elevate: bool, sshd_t: str = ""):
    ex = MagicMock(spec=CommandExecutor)
    ex.mode = SimpleNamespace(value=mode)
    ex.privileges = SimpleNamespace(can_elevate=can_elevate)
    ex.which.side_effect = lambda name: f"/usr/bin/{name}"

    def run(cmd, **kwargs):
        out = sshd_t if cmd[:2] == ["sshd", "-T"] else ""
        return CommandOutput(command=cmd, stdout=out, stderr="", returncode=0,
                             duration_seconds=0.0, success=True, used_sudo=kwargs.get("use_sudo", False))

    ex.run.side_effect = run
    return ex


def test_ssh_collector_is_partial_in_user_mode():
    res = SshCollector().run(_executor("user", can_elevate=False))
    assert res.status == CollectorStatus.PARTIAL
    assert "--mode sudo" in (res.message or "")


def test_ssh_collector_is_success_in_sudo_mode():
    sshd = "port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\n"
    res = SshCollector().run(_executor("sudo", can_elevate=True, sshd_t=sshd))
    assert res.status == CollectorStatus.SUCCESS
    assert res.data["effective_config"]["password_authentication"] == "no"


def _report(mode: str, ssh_status: str, ssh_values: dict, privileged: bool):
    return {
        "metadata": {"hostname": "nodezero", "timestamp": "2026-11-08T00:00:00", "profile": "private",
                     "duration_seconds": 1.0, "tool_name": "serveraudit", "tool_version": "0.1.2",
                     "audit_mode": mode, "privileges_available": privileged},
        "system": {"os": {"pretty_name": "Ubuntu"}, "kernel": {"release": "7", "architecture": "x86_64"}},
        "ssh": {"effective_config": {"port": 22, **ssh_values}},
        "collectors": {
            "ssh": {"status": ssh_status, "duration_seconds": 0.1,
                    "message": "SSH effective config not collected: needs --mode sudo" if ssh_status != "SUCCESS" else "ok"},
            "firewall": {"status": "SKIPPED" if mode == "user" else "SUCCESS", "duration_seconds": 0.0,
                         "message": "requires elevated privileges" if mode == "user" else "ok"},
            "smart": {"status": "SKIPPED" if mode == "user" else "SUCCESS", "duration_seconds": 0.0,
                      "message": "smartctl requires elevated privileges" if mode == "user" else "ok"},
            "cpu": {"status": "SUCCESS", "duration_seconds": 0.1, "message": "ok"},
        },
        "analysis": {"health": [], "exposure": [], "conflicts": []},
        "topology": {"storage_chains": []},
    }


UNKNOWN = {"permit_root_login": "unknown", "password_authentication": "unknown", "pubkey_authentication": "unknown"}


def test_user_mode_report_does_not_present_unknown_ssh_values_as_settings():
    md = MarkdownRenderer.render(_report("user", "PARTIAL", UNKNOWN, privileged=False))
    assert "**PasswordAuthentication:** `unknown`" not in md
    assert "**PermitRootLogin:** `unknown`" not in md
    row = lambda name: next(l for l in md.splitlines() if l.startswith(f"| **{name}**"))
    assert "Configured" not in row("SSH Security")
    assert NOT_COLLECTED in row("SSH Security").lower()
    # root-only modules must not be summarised as "Passed" / "None / Open" when they were skipped
    assert "Passed" not in row("Physical Storage")
    assert NOT_COLLECTED in row("Physical Storage").lower()
    assert "None / Open" not in row("Firewall")
    assert NOT_COLLECTED in row("Firewall").lower()
    assert md.lower().count(NOT_COLLECTED) >= 5
    assert "--mode sudo" in md


def test_user_mode_report_lists_coverage_gaps_in_header():
    md = MarkdownRenderer.render(_report("user", "PARTIAL", UNKNOWN, privileged=False))
    header = md.split("## 📑 Table of Contents")[0]
    assert "Coverage" in header
    assert "`ssh`" in header and "`firewall`" in header
    assert "`cpu`" not in header  # fully collected modules are not listed


def test_sudo_mode_report_is_unchanged():
    values = {"permit_root_login": "no", "password_authentication": "no", "pubkey_authentication": "yes"}
    md = MarkdownRenderer.render(_report("sudo", "SUCCESS", values, privileged=True))
    assert "**PasswordAuthentication:** `no`" in md
    assert "**PermitRootLogin:** `no`" in md
    assert NOT_COLLECTED not in md.lower()
    assert "Coverage" not in md.split("## 📑 Table of Contents")[0]


def test_failed_sudo_in_sudo_mode_still_gets_coverage_block():
    """--mode sudo whose `sudo -v` failed/was cancelled runs without elevation (main.py warns
    and continues); the report must not look like a full audit just because the mode says SUDO."""
    report = _report("sudo", "PARTIAL", UNKNOWN, privileged=False)
    report["collectors"]["firewall"]["status"] = "SKIPPED"
    md = MarkdownRenderer.render(report)
    header = md.split("## 📑 Table of Contents")[0]
    assert "Coverage" in header
    assert "`ssh`" in header and "`firewall`" in header
    assert "sudo" in header.split("Coverage")[1].lower()
