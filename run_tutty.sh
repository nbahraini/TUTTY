#!/usr/bin/env bash
#
# run_tutty.sh
# Clones, installs, and runs nbahraini/TUTTY (pytty) on Linux
#
set -uo pipefail

REPO_URL="https://github.com/nbahraini/TUTTY.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}/TUTTY"
VENV_DIR="${INSTALL_DIR}/.venv"

echo
echo "=== Checking prerequisites ==="

if ! command -v git >/dev/null 2>&1; then
    echo "[ERROR] git was not found on PATH. Install it with your package manager, e.g.:"
    echo "        sudo apt install git       (Debian/Ubuntu)"
    echo "        sudo dnf install git       (Fedora)"
    echo "        sudo pacman -S git         (Arch)"
    exit 1
fi

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] Python was not found on PATH. Install Python 3.10+ with your package manager, e.g.:"
    echo "        sudo apt install python3 python3-venv python3-pip   (Debian/Ubuntu)"
    echo "        sudo dnf install python3                            (Fedora)"
    echo "        sudo pacman -S python                               (Arch)"
    exit 1
fi

PYVER="$("$PYTHON_BIN" --version 2>&1)"
echo "Found $PYVER"

# Basic version check (need >= 3.10)
PYVER_OK=$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
if [ "$PYVER_OK" != "1" ]; then
    echo "[ERROR] Python 3.10 or newer is required. Found: $PYVER"
    exit 1
fi
echo

# ============================================================
# Clone or update the repository
# ============================================================
if [ -d "${INSTALL_DIR}/.git" ]; then
    echo "=== Updating existing clone ==="
    git -C "$INSTALL_DIR" pull
else
    echo "=== Cloning repository ==="
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
echo

# ============================================================
# Create virtual environment (only if missing)
# ============================================================
if [ ! -f "${VENV_DIR}/bin/activate" ]; then
    echo "=== Creating virtual environment ==="
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment."
        echo "        On Debian/Ubuntu you may need: sudo apt install python3-venv"
        exit 1
    fi
fi

echo "=== Activating virtual environment ==="
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
echo

# ============================================================
# Install / update the package
# ============================================================
echo "=== Installing pytty and dependencies ==="
(
    cd "$INSTALL_DIR" || exit 1
    python -m pip install --upgrade pip
    if ! python -m pip install -e ".[keyring]"; then
        echo "[WARN] Install with keyring extra failed, retrying without it..."
        python -m pip install -e .
    fi
)
echo

# ============================================================
# Run pytty
# ============================================================
echo "=== Launching pytty ==="
echo "(Press q or ctrl+] to quit and return here)"
echo
pytty "$@"

deactivate 2>/dev/null || true
echo
echo "Done."