"""
Audit configuration files (`serveraudit audit --config FILE`).

A config file can set the profile, output directory and formats, which collectors run, and the
`mask_*` sanitizer options. Precedence everywhere is: command-line flag > config file > built-in
default. Typos and unknown collector names are errors, never silent no-ops, and `redact_*`
(secret redaction) can never be switched off from a file.

Settings that exist in the YAML templates but have no engine behind them yet (timeouts,
parallelism, ...) are collected in `AuditConfig.ignored` so the CLI can say so.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dependency
    yaml = None

PROFILES = ("private", "public")
FORMATS = ("markdown", "json", "html", "pdf")
# Sanitizer switches a file may set. redact_* may only be confirmed (true), never disabled.
MASK_OPTIONS = ("mask_ips", "mask_macs", "mask_serials", "mask_uuids", "mask_hostname")
REDACT_OPTIONS = ("redact_passwords", "redact_tokens", "redact_private_keys", "redact_env_secrets")

TOP_LEVEL_KEYS = {"version", "profile", "output", "collectors", "sanitization", "execution", "network"}
OUTPUT_KEYS = {"directory", "formats", "generate_checksums", "generate_manifest"}
COLLECTOR_KEYS = {"enabled", "disabled"}
EXECUTION_KEYS = {"timeout_seconds", "parallel_collectors", "max_workers", "allow_sudo"}
NETWORK_KEYS = {"allow_outbound"}


class ConfigError(ValueError):
    """The configuration file is missing, malformed or asks for something unsupported."""


@dataclass
class AuditConfig:
    profile: Optional[str] = None
    output_dir: Optional[str] = None
    formats: Optional[List[str]] = None
    enabled: Optional[List[str]] = None  # None/empty: every collector
    disabled: List[str] = field(default_factory=list)
    sanitization: Dict[str, bool] = field(default_factory=dict)
    ignored: List[str] = field(default_factory=list)  # present in the file but not applied


def _section(raw: Dict[str, Any], key: str, allowed: Set[str], path: str) -> Dict[str, Any]:
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: '{key}' must be a mapping")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) in '{key}': {', '.join(map(str, unknown))} "
                          f"(allowed: {', '.join(sorted(allowed))})")
    return value


def _name_list(value: Any, what: str, path: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{path}: '{what}' must be a list of names")
    return value


def load_config(path: str) -> AuditConfig:
    """Loads and validates a config file. Raises ConfigError with a message naming the problem."""
    p = Path(path)
    if yaml is None:
        raise ConfigError("PyYAML is required to read config files (pip install pyyaml)")
    if not p.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the top level must be a mapping of settings")

    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown setting(s): {', '.join(map(str, unknown))} "
                          f"(allowed: {', '.join(sorted(TOP_LEVEL_KEYS))})")

    cfg = AuditConfig()

    if raw.get("profile") is not None:
        if raw["profile"] not in PROFILES:
            raise ConfigError(f"{path}: profile must be one of {', '.join(PROFILES)} (got {raw['profile']!r})")
        cfg.profile = raw["profile"]

    output = _section(raw, "output", OUTPUT_KEYS, path)
    if output.get("directory") is not None:
        if not isinstance(output["directory"], str) or not output["directory"].strip():
            raise ConfigError(f"{path}: output.directory must be a non-empty string")
        cfg.output_dir = output["directory"]
    if output.get("formats") is not None:
        formats = _name_list(output["formats"], "output.formats", path)
        bad = sorted(set(formats) - set(FORMATS))
        if bad:
            raise ConfigError(f"{path}: unknown output format(s): {', '.join(bad)} (choose from {', '.join(FORMATS)})")
        cfg.formats = formats
    for key in ("generate_checksums", "generate_manifest"):
        if output.get(key) is False:
            cfg.ignored.append(f"output.{key}")  # bundles always include both

    collectors = _section(raw, "collectors", COLLECTOR_KEYS, path)
    if collectors.get("enabled") is not None:
        cfg.enabled = _name_list(collectors["enabled"], "collectors.enabled", path)
    if collectors.get("disabled") is not None:
        cfg.disabled = _name_list(collectors["disabled"], "collectors.disabled", path)

    san = _section(raw, "sanitization", set(MASK_OPTIONS) | set(REDACT_OPTIONS), path)
    for key, value in san.items():
        if not isinstance(value, bool):
            raise ConfigError(f"{path}: sanitization.{key} must be true or false (got {value!r})")
        if key in REDACT_OPTIONS and value is False:
            raise ConfigError(f"{path}: sanitization.{key}: secret redaction cannot be disabled from a config file")
        cfg.sanitization[key] = value

    # Known keys with no engine behind them yet: report instead of pretending.
    execution = _section(raw, "execution", EXECUTION_KEYS, path)
    for key, value in execution.items():
        satisfied = (key == "allow_sudo" and value is True) or (key == "parallel_collectors" and value is False)
        if not satisfied:
            cfg.ignored.append(f"execution.{key}")
    network = _section(raw, "network", NETWORK_KEYS, path)
    if network.get("allow_outbound") is True:
        cfg.ignored.append("network.allow_outbound")

    return cfg


def validate_collector_names(cfg: AuditConfig, known: Set[str]) -> None:
    """Rejects collector names that do not exist, so a typo cannot silently disable nothing."""
    wanted = set(cfg.enabled or []) | set(cfg.disabled)
    unknown = sorted(wanted - set(known))
    if unknown:
        raise ConfigError(f"unknown collector name(s) in config: {', '.join(unknown)} "
                          f"(valid: {', '.join(sorted(known))})")
