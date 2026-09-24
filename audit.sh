#!/usr/bin/env bash
# ==============================================================================
# Linux Server Audit Launcher
#
# Validates sudo privileges once and launches the Python auditing engine
# with least privilege.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}/src:${PYTHONPATH:-}"

echo "======================================================================"
echo " Linux Server Audit"
echo "======================================================================"
echo "An observational, read-only Linux server audit is about to begin."
echo "Elevated privileges are required for protected hardware, storage,"
echo "security, and service inspection."
echo "No intentional system configuration changes will occur."
echo "----------------------------------------------------------------------"

# Authenticate sudo once if available
if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
        echo "✓ Sudo credentials already active."
    else
        echo "Please authenticate sudo once for privileged collectors:"
        sudo -v
        echo "✓ Sudo authenticated successfully."
    fi
    # Keep sudo timestamp alive in background during long audits
    (while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done) 2>/dev/null &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null || true' EXIT
else
    echo "Notice: 'sudo' not found. Audit will proceed with available unprivileged collectors."
fi

# Locate Python 3 (.venv preferred)
PYTHON_BIN=""
if [ -f "${SCRIPT_DIR}/.venv/bin/python" ]; then
    PYTHON_BIN="${SCRIPT_DIR}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Error: Python 3.10+ is required. Please run './install.sh' first." >&2
    exit 1
fi

# Execute audit CLI passing through all arguments
exec "$PYTHON_BIN" -m serveraudit.cli.main audit "$@"
