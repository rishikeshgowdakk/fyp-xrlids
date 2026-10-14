from __future__ import annotations

from pathlib import Path
import sys
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import REPO_ROOT as SERVER_REPO_ROOT, DASHBOARD_DIR, FIGURES_DIR, get_dashboard_data


def test_dashboard_files_exist():
    assert DASHBOARD_DIR.exists()
    assert (DASHBOARD_DIR / "index.html").is_file()
    assert (DASHBOARD_DIR / "app.js").is_file()
    assert (DASHBOARD_DIR / "server.py").is_file()
    assert (DASHBOARD_DIR / "README.md").is_file()


def test_get_dashboard_data_structure():
    data = get_dashboard_data()
    assert isinstance(data, dict)
    assert "status" in data
    assert data["status"] == "ready"
    assert "replay" in data
    assert "shap" in data
    assert "figures" in data
    assert isinstance(data["figures"], list)
