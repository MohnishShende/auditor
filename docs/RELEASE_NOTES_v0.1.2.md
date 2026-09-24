# Auditor v0.1.2 — Docker Container Inventory Fix

Auditor v0.1.2 resolves a critical issue affecting Docker container discovery and command execution with formatted parameters.

---

### 🐛 Bug Fixes & Improvements

1. **Executor Safety Denylist False Positive Elimination**:
   - Fixed `CommandExecutor.is_safe_command` where arguments containing the substring `rm` (such as `--format '{{json .}}'`) were mistakenly blocked as dangerous commands.
   - Refactored safety verification into exact binary matching (`FORBIDDEN_BINARIES`) and regex word-boundary pattern matching (`FORBIDDEN_PATTERNS`).

2. **Docker Container Inventory & NDJSON Parsing**:
   - Implemented native newline-delimited JSON (NDJSON) parsing from `docker ps -a --format '{{json .}}'`.
   - Comprehensive extraction of container identity, status, images, networks, ports, volume mounts, and Docker Compose project/service metadata.
   - Fully tested and validated against real production hosts running Docker Engine 29.8.1.

---

### 🧪 Validation
- Complete test suite: 27 passing tests (100% pass rate).
- Validated on real Ubuntu 26.04 server (NodeZero) with 9 running production containers.
