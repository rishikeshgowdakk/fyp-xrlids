#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$DIR/.venv/bin/python"
PYTEST="$DIR/.venv/bin/pytest"

if [ ! -x "$PYTHON" ] || [ ! -x "$PYTEST" ]; then
    echo "ERROR: Virtual environment not found or python/pytest executable is missing at:"
    echo "  $DIR/.venv"
    echo ""
    echo "Please set up the virtual environment before running this script:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install -r requirements.txt"
    exit 1
fi

case "${1:-dashboard}" in
    dashboard|dash|web)
        echo "Starting XRL-IDARS Dashboard at http://localhost:${2:-8000} ..."
        "$PYTHON" "$DIR/dashboard/server.py" "${2:-8000}"
        ;;
    demo|replay)
        echo "Running PCAP replay demo..."
        "$PYTHON" "$DIR/scripts/demo/run_replay_demo.py"
        ;;
    test)
        echo "Running test suite..."
        "$PYTEST" -q
        ;;
    help|-h|--help)
        echo "Usage: ./run.sh [dashboard|demo|test]"
        exit 0
        ;;
    *)
        echo "Usage: ./run.sh [dashboard|demo|test]"
        exit 1
        ;;
esac
