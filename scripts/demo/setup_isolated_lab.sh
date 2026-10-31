#!/usr/bin/env bash
# XRL-IDARS — Setup Isolated Lab Network Topology
# Delegates directly to the canonical privileged helper scripts/demo/lab_privileged_helper.py

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PY_BIN="$REPO_ROOT/.venv/bin/python"
if [ ! -f "$PY_BIN" ]; then
    PY_BIN="$(command -v python3)"
fi

echo "[*] Executing XRL-IDARS Privileged Lab Setup..."
if [ "$(id -u)" -eq 0 ]; then
    "$PY_BIN" "$SCRIPT_DIR/lab_privileged_helper.py" setup
else
    if sudo -n true 2>/dev/null; then
        sudo "$PY_BIN" "$SCRIPT_DIR/lab_privileged_helper.py" setup
    elif command -v pkexec >/dev/null 2>&1 && [ -n "${DISPLAY:-${WAYLAND_DISPLAY:-}}" ]; then
        pkexec "$PY_BIN" "$SCRIPT_DIR/lab_privileged_helper.py" setup
    else
        echo "[!] Administrative privileges required. Running with sudo..."
        sudo "$PY_BIN" "$SCRIPT_DIR/lab_privileged_helper.py" setup
    fi
fi
