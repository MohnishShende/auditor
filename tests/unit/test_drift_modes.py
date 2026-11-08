"""
Comparing a user-mode snapshot with a sudo-mode one must not report root-only data that
the unprivileged run could not read ("unknown", empty sudo list) as configuration drift.
"""

from serveraudit.analysis.drift import compare_snapshots


def _snap(privileged: bool, ssh: dict, ssh_status: str, sudo_users, ports_status="SUCCESS", ports=()):
    return {
        "metadata": {"audit_mode": "sudo" if privileged else "user", "privileges_available": privileged},
        "ssh": {"effective_config": {"port": 22, **ssh}},
        "users": {"users": [{"username": "root"}, {"username": "nodezero"}],
                  "sudo_users": [{"username": u} for u in sudo_users]},
        "ports": {"listening_ports": [{"protocol": "tcp", "port": p} for p in ports]},
        "collectors": {
            "ssh": {"status": ssh_status},
            "users": {"status": "SUCCESS" if privileged else "PARTIAL"},
            "ports": {"status": ports_status},
        },
    }


UNKNOWN = {"permit_root_login": "unknown", "password_authentication": "unknown", "pubkey_authentication": "unknown"}
KNOWN = {"permit_root_login": "no", "password_authentication": "no", "pubkey_authentication": "yes"}


def test_user_vs_sudo_snapshot_reports_no_false_ssh_or_sudo_drift():
    a = _snap(False, UNKNOWN, "PARTIAL", sudo_users=[])
    b = _snap(True, KNOWN, "SUCCESS", sudo_users=["nodezero"])
    d = compare_snapshots(a, b)
    assert "SSH Configuration" not in d["categories"]
    assert "Users & Groups" not in d["categories"]
    assert d["has_drift"] is False
    skipped = {n["category"]: n["reason"] for n in d["not_compared"]}
    assert set(skipped) >= {"SSH Configuration", "Users & Groups"}
    assert all("--mode sudo" in r for r in skipped.values())


def test_sudo_vs_sudo_real_drift_is_still_detected():
    a = _snap(True, KNOWN, "SUCCESS", sudo_users=["nodezero"])
    b = _snap(True, {**KNOWN, "password_authentication": "yes"}, "SUCCESS", sudo_users=["nodezero", "mallory"])
    d = compare_snapshots(a, b)
    assert d["has_drift"] is True
    assert d["categories"]["SSH Configuration"] == [{"setting": "password_authentication", "old": "no", "new": "yes"}]
    assert d["categories"]["Users & Groups"]["added_sudo"] == ["mallory"]
    assert d["not_compared"] == []


def test_privileged_snapshot_with_a_failed_collector_is_not_treated_as_unprivileged():
    # A genuine collector failure on a privileged run is not a privilege gap: keep comparing.
    a = _snap(True, KNOWN, "SUCCESS", sudo_users=["nodezero"])
    b = _snap(True, {**KNOWN, "port": 2222}, "PARTIAL", sudo_users=["nodezero"])
    assert "SSH Configuration" in compare_snapshots(a, b)["categories"]


def test_snapshots_without_collector_metadata_compare_as_before():
    a = {"ssh": {"effective_config": {"port": 22, "password_authentication": "no"}}}
    b = {"ssh": {"effective_config": {"port": 22, "password_authentication": "yes"}}}
    d = compare_snapshots(a, b)
    assert d["categories"]["SSH Configuration"][0]["new"] == "yes"
    assert d["not_compared"] == []


def test_cli_diff_does_not_claim_no_drift_when_categories_were_not_compared(tmp_path, capsys):
    import json
    from serveraudit.cli.diff import run_diff

    for name, snap in (("a", _snap(False, UNKNOWN, "PARTIAL", [])), ("b", _snap(True, KNOWN, "SUCCESS", ["nodezero"]))):
        d = tmp_path / name
        d.mkdir()
        snap["metadata"].update(hostname="nodezero", timestamp="t")
        (d / "audit.json").write_text(json.dumps(snap), encoding="utf-8")
    assert run_diff(str(tmp_path / "a"), str(tmp_path / "b")) == 0
    out = capsys.readouterr().out
    assert "NOT COMPARED" in out and "SSH Configuration" in out and "--mode sudo" in out
    assert "No configuration drift detected" not in out
