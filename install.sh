#!/usr/bin/env bash
# ==============================================================================
# Linux Server Audit - Automated Installer & Environment Setup
#
# Creates a project-isolated Python virtual environment, verifies dependencies,
# and exposes the 'serveraudit' command cleanly.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo -e "${BLUE}${BOLD} Linux Server Audit - Installer${NC}"
echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo "Setting up project-isolated environment for Linux Server Audit..."
echo ""

# 1. Detect Linux Distribution
OS_NAME="Linux"
OS_ID="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-$NAME}"
    OS_ID="${ID:-unknown}"
fi
echo -e "Detected OS: ${BOLD}${OS_NAME}${NC}"

# 2. Check Python 3 Availability (Python 3.10+)
PYTHON_BIN=""
for cand in python3 python python3.12 python3.11 python3.10; do
    if command -v "$cand" >/dev/null 2>&1; then
        PY_VER=$("$cand" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            PYTHON_BIN="$cand"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}${BOLD}Error: Python 3.10 or higher is required but was not found.${NC}"
    echo ""
    echo "Please install Python 3.10+ using your package manager:"
    if [[ "$OS_ID" =~ ^(ubuntu|debian|linuxmint|pop)$ ]]; then
        echo -e "  ${BOLD}sudo apt update && sudo apt install -y python3 python3-venv python3-pip${NC}"
    elif [[ "$OS_ID" =~ ^(fedora|rhel|centos|rocky|alma)$ ]]; then
        echo -e "  ${BOLD}sudo dnf install -y python3 python3-pip${NC}"
    elif [[ "$OS_ID" =~ ^(arch|manjaro)$ ]]; then
        echo -e "  ${BOLD}sudo pacman -S python python-pip${NC}"
    elif [ "$OS_ID" = "alpine" ]; then
        echo -e "  ${BOLD}apk add python3 py3-pip${NC}"
    else
        echo -e "  ${BOLD}Install Python 3.10+ and pip via your system package manager.${NC}"
    fi
    exit 1
fi

echo -e "Using Python: ${GREEN}${PYTHON_BIN}${NC} ($("$PYTHON_BIN" --version))"

# 3. Verify python3-venv module
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    echo -e "${RED}${BOLD}Error: Python 'venv' module is missing.${NC}"
    echo ""
    if [[ "$OS_ID" =~ ^(ubuntu|debian|linuxmint|pop)$ ]]; then
        echo -e "Please run: ${BOLD}sudo apt update && sudo apt install -y python3-venv${NC}"
    else
        echo "Please install the python3 venv package for your distribution."
    fi
    exit 1
fi

# 4. Create Project-Isolated Virtual Environment (.venv)
VENV_DIR="${SCRIPT_DIR}/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in ${VENV_DIR}..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists in ${VENV_DIR}."
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# 5. Install Dependencies into .venv
echo "Installing/updating dependencies in virtual environment..."
"$VENV_PIP" install --upgrade pip --quiet
"$VENV_PIP" install -e . --quiet

# 6. Create clean user executable wrappers
mkdir -p "${SCRIPT_DIR}/bin"
WRAPPER="${SCRIPT_DIR}/bin/serveraudit"

cat <<EOF > "$WRAPPER"
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="\${SCRIPT_DIR}/src:\${PYTHONPATH:-}"
if [ -f "\${SCRIPT_DIR}/.venv/bin/python" ]; then
    exec "\${SCRIPT_DIR}/.venv/bin/python" -m serveraudit.cli.main "\$@"
else
    exec python3 -m serveraudit.cli.main "\$@"
fi
EOF

chmod +x "$WRAPPER"
ln -sf "$WRAPPER" "${SCRIPT_DIR}/bin/nodeaudit"

# Optional: Add symlink to ~/.local/bin if directory exists
LOCAL_BIN="${HOME}/.local/bin"
if [ -d "$LOCAL_BIN" ] && [[ ":$PATH:" == *":$LOCAL_BIN:"* ]]; then
    ln -sf "$WRAPPER" "${LOCAL_BIN}/serveraudit"
    ln -sf "$WRAPPER" "${LOCAL_BIN}/nodeaudit"
    echo -e "Linked CLI to: ${GREEN}${LOCAL_BIN}/serveraudit${NC}"
fi

# 7. Self-Verification
echo "Verifying installation..."
if "${SCRIPT_DIR}/bin/serveraudit" --version >/dev/null 2>&1; then
    VERSION_STR=$("${SCRIPT_DIR}/bin/serveraudit" --version)
    echo -e "${GREEN}${BOLD}✓ Installation verified successfully! (${VERSION_STR})${NC}"
else
    echo -e "${RED}${BOLD}Verification failed. Please check error logs.${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD} Ready to Audit!${NC}"
echo -e "${BLUE}${BOLD}======================================================================${NC}"
echo "To run your first server audit, execute:"
echo ""
echo -e "  ${BOLD}./audit.sh${NC}"
echo ""
echo "Or using the direct CLI:"
echo ""
echo -e "  ${BOLD}./bin/serveraudit audit${NC}"
echo ""
echo "All audit reports will be stored in: ${SCRIPT_DIR}/audits/"
echo "======================================================================"
