"""
`--config FILE` used to be accepted and ignored (the orchestrator stored config_file and never
read it; `--profile private` "won" over public.yaml only because nothing was applied). It now
loads, validates and applies the file: CLI flag > config file > built-in default.
"""

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from serveraudit.cli.audit import AuditOrchestrator
from serveraudit.cli.main import resolve_audit_settings
from serveraudit.collectors import get_all_collectors
from serveraudit.core.config import AuditConfig, ConfigError, load_config, validate_collector_names

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@pytest.fixture(autouse=True)
def _as_linux():
    with patch("serveraudit.cli.audit.platform.system", return_value="Linux"):
        yield


def _write(tmp_path, body):
    p = tmp_path / "c.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(p)


# ------------------------------------------------------------------ loading

def test_valid_config_is_loaded(tmp_path):
    cfg = load_config(_write(tmp_path, """
        version: "1.0"
        profile: public
        output:
          directory: /srv/audits
          formats: [markdown, json]
        collectors:
          enabled: [system, cpu, docker]
          disabled: [docker]
        sanitization:
          mask_hostname: false
          mask_ips: true
    """))
    assert cfg.profile == "public" and cfg.output_dir == "/srv/audits" and cfg.formats == ["markdown", "json"]
    assert cfg.enabled == ["system", "cpu", "docker"] and cfg.disabled == ["docker"]
    assert cfg.sanitization == {"mask_hostname": False, "mask_ips": True}
    assert cfg.ignored == []


def test_empty_config_is_valid_and_sets_nothing(tmp_path):
    cfg = load_config(_write(tmp_path, "{}\n"))
    assert cfg == AuditConfig()


@pytest.mark.parametrize("body,needle", [
    ("profile: secret\n", "profile"),
    ("output:\n  formats: [markdown, docx]\n", "docx"),
    ("output:\n  formats: markdown\n", "formats"),
    ("sanitization:\n  mask_hostnam: true\n", "mask_hostnam"),
    ("sanitization:\n  mask_ips: yes please\n", "mask_ips"),
    ("sanitization:\n  redact_passwords: false\n", "redact_passwords"),
    ("sanitization:\n  redact_tokens: false\n", "redact_tokens"),
    ("collectors:\n  enabled: system\n", "enabled"),
    ("- just\n- a list\n", "mapping"),
    ("profile: [unclosed\n", "YAML"),
])
def test_invalid_config_is_rejected_with_a_clear_message(tmp_path, body, needle):
    with pytest.raises(ConfigError) as e:
        load_config(_write(tmp_path, body))
    assert needle in str(e.value)


def test_redact_settings_may_be_true_but_never_turned_off(tmp_path):
    cfg = load_config(_write(tmp_path, "sanitization:\n  redact_passwords: true\n  redact_private_keys: true\n"))
    assert cfg.sanitization == {"redact_passwords": True, "redact_private_keys": True}


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(str(tmp_path / "nope.yaml"))
    assert "nope.yaml" in str(e.value)


def test_settings_without_an_engine_behind_them_are_reported_not_silently_ignored(tmp_path):
    cfg = load_config(_write(tmp_path, """
        execution:
          timeout_seconds: 5
          parallel_collectors: true
        network:
          allow_outbound: true
    """))
    assert set(cfg.ignored) == {"execution.timeout_seconds", "execution.parallel_collectors", "network.allow_outbound"}


def test_unknown_top_level_keys_are_errors(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(_write(tmp_path, "profil: public\n"))
    assert "profil" in str(e.value)


def test_collector_names_are_validated_against_the_registry():
    known = set(get_all_collectors())
    validate_collector_names(AuditConfig(enabled=["system"], disabled=["docker"]), known)
    with pytest.raises(ConfigError) as e:
        validate_collector_names(AuditConfig(enabled=["system", "dockr"]), known)
    assert "dockr" in str(e.value)


@pytest.mark.parametrize("name", ["default.yaml", "private.yaml", "public.yaml"])
def test_the_shipped_config_files_load_cleanly(name):
    cfg = load_config(str(CONFIG_DIR / name))
    validate_collector_names(cfg, set(get_all_collectors()))
    assert cfg.ignored == [], f"{name} sets options the tool cannot apply: {cfg.ignored}"


# --------------------------------------------------------------- precedence

def test_cli_flag_beats_config_beats_default():
    cfg = AuditConfig(profile="public", output_dir="/cfg", formats=["json"])
    assert resolve_audit_settings("private", "/cli", "html", cfg) == ("private", "/cli", ["html"])
    assert resolve_audit_settings(None, None, None, cfg) == ("public", "/cfg", ["json"])
    assert resolve_audit_settings(None, None, None, AuditConfig()) == ("private", "audits", ["markdown", "json", "html"])
    assert resolve_audit_settings(None, None, None, None) == ("private", "audits", ["markdown", "json", "html"])


# ------------------------------------------------------- applied end to end

def _collectors(snap):
    return json.loads((snap / "audit.json").read_text())["collectors"]


def test_disabled_collectors_are_skipped_and_say_why(tmp_path):
    snap = AuditOrchestrator(output_dir=str(tmp_path), quiet=True,
                             audit_config=AuditConfig(disabled=["docker", "caddy"])).run_audit()
    c = _collectors(snap)
    for name in ("docker", "caddy"):
        assert c[name]["status"] == "SKIPPED" and "configuration" in c[name]["message"].lower()
    assert c["system"]["status"] == "SUCCESS"


def test_enabled_list_restricts_the_audit_to_those_collectors(tmp_path):
    snap = AuditOrchestrator(output_dir=str(tmp_path), quiet=True,
                             audit_config=AuditConfig(enabled=["system", "cpu"])).run_audit()
    c = _collectors(snap)
    assert c["system"]["status"] == "SUCCESS"
    others = {n for n, v in c.items() if n not in ("system", "cpu")}
    assert others and all(c[n]["status"] == "SKIPPED" and "configuration" in c[n]["message"].lower() for n in others)


def test_sanitization_overrides_are_applied(tmp_path):
    fake = "secret-host-01.corp.example"
    with patch("serveraudit.cli.audit.platform.node", return_value=fake):
        keep = AuditOrchestrator(profile="public", output_dir=str(tmp_path / "a"), quiet=True,
                                 audit_config=AuditConfig(enabled=["system"], sanitization={"mask_hostname": False})).run_audit()
        hide = AuditOrchestrator(profile="private", output_dir=str(tmp_path / "b"), quiet=True,
                                 audit_config=AuditConfig(enabled=["system"], sanitization={"mask_hostname": True})).run_audit()
    assert fake in (keep / "audit.json").read_text()
    assert "secret-host-01" not in (hide / "audit.json").read_text().lower()
