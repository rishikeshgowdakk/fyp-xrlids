#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$DIR/.venv/bin/python"
PYTEST="$DIR/.venv/bin/pytest"

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
