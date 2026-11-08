"""
sudo validation must work for passwordless users on sudo-rs (Ubuntu's default sudo),
where `sudo -v` demands authentication even with NOPASSWD but `sudo -n <cmd>` works,
and must never hang or prompt without a terminal.
"""

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from serveraudit.core.privileges import AuditMode, PrivilegeManager


def _run_factory(passwordless: bool, calls: list):
    """Models sudo-rs: `-n <cmd>` honours NOPASSWD; `-v` always wants interactive auth."""
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["sudo", "-n"] and len(cmd) > 2 and cmd[2] != "-v":
            return subprocess.CompletedProcess(cmd, 0 if passwordless else 1)
        if cmd == ["sudo", "-v"]:
            return subprocess.CompletedProcess(cmd, 0 if kwargs.get("_interactive_ok") else 1)
        return subprocess.CompletedProcess(cmd, 1)
    return fake_run


def _validate(passwordless: bool, tty: bool):
    calls: list = []
    pm = PrivilegeManager(mode=AuditMode.SUDO)
    pm._is_root = False
    with patch("serveraudit.core.privileges.shutil.which", return_value="/usr/bin/sudo"), \
         patch("serveraudit.core.privileges.subprocess.run", side_effect=_run_factory(passwordless, calls)), \
         patch("sys.stdin", new=SimpleNamespace(isatty=lambda: tty)):
        ok = pm.validate_sudo()
    return ok, calls


def test_passwordless_sudo_is_detected_without_sudo_v():
    ok, calls = _validate(passwordless=True, tty=False)
    assert ok is True
    assert ["sudo", "-v"] not in calls  # sudo-rs would demand a password / a terminal here


def test_passwordless_sudo_is_detected_even_with_a_tty_and_never_prompts():
    ok, calls = _validate(passwordless=True, tty=True)
    assert ok is True
    assert ["sudo", "-v"] not in calls


def test_password_user_with_tty_falls_back_to_interactive_sudo_v_once():
    ok, calls = _validate(passwordless=False, tty=True)
    assert ["sudo", "-v"] in calls and calls.count(["sudo", "-v"]) == 1
    assert ok is False  # fake -v refuses; the point is that the interactive path is attempted


def test_no_tty_and_no_passwordless_sudo_never_attempts_interactive_prompt():
    ok, calls = _validate(passwordless=False, tty=False)
    assert ok is False
    assert ["sudo", "-v"] not in calls


def test_user_mode_still_spawns_no_sudo_process():
    calls: list = []
    pm = PrivilegeManager(mode=AuditMode.USER)
    with patch("serveraudit.core.privileges.subprocess.run", side_effect=_run_factory(True, calls)):
        assert pm.validate_sudo() is False
    assert calls == []
