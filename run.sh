set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================================"
echo " TraceHunter: Host-Based Threat Hunting & Live Process Forensic Engine"
echo " Repository: https://github.com/x90d-dev/TraceHunter"
echo "============================================================================"
echo ""

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[ERROR] Python 3.9+ was not found in system PATH."
    exit 1
fi

if ! "$PYTHON_BIN" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >/dev/null 2>&1; then
    echo "[ERROR] TraceHunter requires Python 3.9 or newer."
    "$PYTHON_BIN" --version
    exit 1
fi

if [ ! -f ".venv/bin/activate" ]; then
    echo "[INFO] Creating isolated Python virtual environment in .venv ..."
    "$PYTHON_BIN" -m venv .venv || {
        echo "[ERROR] Failed to initialize virtual environment (.venv)."
        exit 1
    }
fi

source ".venv/bin/activate"

if [ ! -f ".venv/installed_marker.txt" ]; then
    if [ -f "requirements.txt" ]; then
        echo "[INFO] Upgrading pip silently..."
        python -m pip install --upgrade pip >/dev/null 2>&1 || true
        echo "[INFO] Installing dependencies from requirements.txt..."
        if pip install -r requirements.txt; then
            date -u +"Installed on %Y-%m-%dT%H:%M:%SZ" > ".venv/installed_marker.txt"
            echo "[INFO] Dependencies installed and verified."
            echo ""
        else
            echo "[ERROR] Failed to install packages from requirements.txt."
            exit 1
        fi
    fi
fi

echo "[INFO] Launching TraceHunter host forensic inspection..."
echo ""
if [ "$#" -eq 0 ]; then
    python tracehunter.py --scan-all
else
    python tracehunter.py "$@"
fi
