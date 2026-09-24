# Auditor v0.1.1 — Linux Deployment & Collector Fixes

Auditor v0.1.1 is a targeted bug-fix release addressing observations from production deployment testing on real Linux environments (Ubuntu 26.04 / Linux 7.0 / Docker 29.8).

---

### 🐛 Bug Fixes & Improvements

1. **CLI Wrapper Symlink Resolution (Bug 1)**:
   - Fixed project root and virtual environment path derivation in `install.sh`, `audit.sh`, and `bin/serveraudit`.
   - The CLI wrapper now resolves symlinks cleanly, enabling invocation via `serveraudit`, `~/.local/bin/serveraudit`, `./bin/serveraudit`, or custom symlink paths without `ModuleNotFoundError`.

2. **CPU Collector Resilience & Multi-Arch Fallback (Bug 2)**:
   - Fixed `KeyError: 'model_name'` caused by key mismatch when parsing `/proc/cpuinfo`.
   - Added cross-architecture field matching (x86, ARM, RISC-V) and `lscpu -J` integration.
   - Guarded optional metadata access to return `PARTIAL` rather than failing the collector when optional fields are unavailable.

3. **Docker Detection & Multi-Tier Error Differentiation (Bug 3)**:
   - Fixed a false-negative issue where operational Docker daemons were reported as `SKIPPED`.
   - Added support for Docker Engine 29.x / API 1.56, unprivileged execution with automatic privilege elevation fallback, and explicit status differentiation (`SKIPPED` for missing CLI/stopped daemon, `PERMISSION_DENIED` for socket permissions, `SUCCESS` for running daemon).

4. **Eliminated runpy RuntimeWarning on CLI Execution (Bug 4)**:
   - Refactored `serveraudit.cli.__init__` with lazy attribute loading to eliminate `<frozen runpy>: RuntimeWarning` when executing `python -m serveraudit.cli.main`.

---

### 🧪 Validation
- Complete test suite: 25 passing test cases (100% pass rate).
- Added regression tests covering symlink wrapper structure, CPU tolerant parsing, Docker status differentiation, Docker 29.x payloads, and CLI module loading.
