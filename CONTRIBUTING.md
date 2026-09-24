# Contributing to Linux Server Audit

Thank you for your interest in contributing! Linux Server Audit is built to provide trustworthy, observational documentation of Linux systems.

## Core Contributing Invariants

1. **Observational Safety**: No collector may execute commands that change system configuration, install/remove packages, restart services, alter firewall rules, or modify files outside the project audit directory.
2. **Deterministic & Structured**: Collectors must return structured Python dictionaries / dataclasses, not pre-rendered Markdown strings.
3. **Secret Protection**: Never write collectors that export private keys, cleartext passwords, or unredacted credentials.
4. **Resilience**: Every collector must handle missing commands, non-root environments, command timeouts, and malformed command outputs gracefully.
5. **Least Privilege**: Only request elevated privileges (`requires_root = True` in manifest) if genuinely necessary (e.g. `dmidecode`, `smartctl`).

## Adding a Collector

1. Implement collector class extending `BaseCollector` in `src/serveraudit/collectors/<name>/collector.py`.
2. Define `manifest.yaml` specifying commands executed, privileged requirements, and outputs.
3. Add unit test with realistic mocked command fixtures in `tests/unit/` or `tests/fixtures/`.
4. Register the collector in the collector registry.
5. Update docs in `docs/collectors.md`.

## Running Tests

```bash
pytest tests/
```
