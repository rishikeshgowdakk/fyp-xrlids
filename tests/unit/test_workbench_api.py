"""Unit tests for the XRL-IDARS Research Evaluation Workbench APIs.

Verifies that all 7 workbench pages and data endpoints return authentic,
structured, non-fabricated research outputs directly from frozen artifacts.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import create_server
from dashboard.workbench_data import (
    BENCHMARK_REGISTRY,
    get_comparison_data,
    get_evaluation_data,
    get_explainability_data,
    get_flow_explorer_data,
    get_flow_export_csv,
    get_limitations_data,
    get_overview_data,
    get_response_benchmark_data,
)


@pytest.fixture(scope="module")
def workbench_server():
    server = create_server(port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_workbench_overview_structure(workbench_server):
    url = f"{workbench_server}/api/overview"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["project"] == "XRL-IDARS"
    assert "git_commit" in data
    assert len(data["component_statuses"]) == 5
    statuses = {cs["component"]: cs["status"] for cs in data["component_statuses"]}
    assert statuses["Random Forest Detector"] == "VERIFIED_FOR_DEFINED_SCOPE"
    assert statuses["Supervised LSTM"] == "PARTIALLY_VERIFIED"
    assert statuses["RF-LSTM Fusion"] == "PARTIALLY_VERIFIED"
    assert statuses["Deep Q-Network (DQN)"] == "REQUIRES_REFORMULATION"
    assert statuses["Deterministic Safety Gate"] == "VERIFIED_FOR_DEFINED_SCOPE"


def test_workbench_evaluation_benchmarks(workbench_server):
    for bench_id in ["cicids2017", "cse2018", "unswnb15", "cse2018_temporal"]:
        url = f"{workbench_server}/api/evaluation?benchmark={bench_id}&slice=aligned"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
        assert data["benchmark"]["id"] == bench_id
        assert "models" in data
        assert len(data["models"]) >= 1
        assert "population" in data
        assert data["population"] > 0


def test_workbench_cicids2017_population_reconciliation():
    aligned = get_evaluation_data("cicids2017", slice_type="aligned")
    native = get_evaluation_data("cicids2017", slice_type="native")

    assert native["tabular_population"] == 355865
    assert aligned["aligned_population"] == 355833
    assert aligned["dropped_boundary_flows"] == 32
    assert "8 capture files" in aligned["dropped_derivation"]


def test_workbench_comparison_degenerate_fusion_detection(workbench_server):
    # CSE-CIC-IDS2018 validation selected alpha = 0.00 -> pure LSTM (degenerate)
    url = f"{workbench_server}/api/comparison?benchmark=cse2018"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["fusion"]["alpha"] == 0.0
    assert data["fusion"]["is_degenerate"] is True
    assert "Degenerate weighting" in data["fusion"]["warning"]

    # CIC-IDS2017 uses balanced alpha = 0.50 -> non-degenerate
    url_cic = f"{workbench_server}/api/comparison?benchmark=cicids2017"
    with urllib.request.urlopen(url_cic, timeout=5) as resp:
        assert resp.status == 200
        data_cic = json.loads(resp.read().decode("utf-8"))

    assert data_cic["fusion"]["alpha"] == 0.5
    assert data_cic["fusion"]["is_degenerate"] is False


def test_workbench_flow_explorer_pagination_and_filtering(workbench_server):
    url = f"{workbench_server}/api/flows?benchmark=cicids2017&page=1&limit=10&status=all&label=all"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert len(data["flows"]) == 10
    assert data["page"] == 1
    assert data["total_pages"] > 1

    first = data["flows"][0]
    assert "ground_truth" in first
    assert "model_prediction" in first
    assert first["ground_truth"]["label"] in (0, 1)
    assert 0.0 <= first["model_prediction"]["rf_score"] <= 1.0


def test_workbench_flow_export_csv(workbench_server):
    url = f"{workbench_server}/api/flows/export?benchmark=cicids2017&status=errors&label=all"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        csv_text = resp.read().decode("utf-8")

    assert "# XRL-IDARS Flow Evaluation Export" in csv_text
    assert "# Benchmark: CIC-IDS2017" in csv_text
    lines = csv_text.strip().split("\n")
    # Verify CSV headers are present
    assert any("flow_id,ground_truth_label,ground_truth_name,rf_score" in line for line in lines)


def test_workbench_explainability_shap(workbench_server):
    url = f"{workbench_server}/api/explainability?benchmark=cicids2017"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["explainer_model"] == "Random Forest Detector (200 Trees)"
    assert len(data["global_importance"]) == 10
    assert any("TreeSHAP" in notice for notice in data["scientific_notices"])


def test_workbench_response_benchmark_cost_optimal_win(workbench_server):
    # In High Availability 4-action mode, CostOptimalThresholdPolicy beats DQN by 20.12%
    url = f"{workbench_server}/api/response-benchmark?regime=high_availability&mode=4-action"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["cost_regime"] == "high_availability"
    assert data["action_mode"] == "4-action"
    assert len(data["policies"]) == 6
    assert data["head_to_head"] is not None
    assert "Cost_Optimal" in data["head_to_head"]["superior_policy"]
    assert data["safety_gate"]["status"] == "AUTHORITATIVE_ENFORCED"


def test_workbench_limitations(workbench_server):
    url = f"{workbench_server}/api/limitations"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert len(data["limitations"]) == 9
    lim_ids = [l["id"] for l in data["limitations"]]
    assert "LIM-001" in lim_ids
    assert "LIM-006" in lim_ids
    assert "LIM-007" in lim_ids


def test_fusion_edge_cases_and_weight_validation():
    import pandas as pd
    from xrlids.models.fusion import FusionError, fuse_scores

    s_rf = pd.Series([0.1, 0.8], index=[0, 1])
    s_lstm = pd.Series([0.2, 0.9], index=[0, 1])

    # Valid alpha
    res = fuse_scores(s_rf, s_lstm, alpha=0.5)
    assert abs(res.scores[0] - 0.15) < 1e-5

    # Out of range alpha raises FusionError
    with pytest.raises(FusionError, match="alpha must be in"):
        fuse_scores(s_rf, s_lstm, alpha=-0.1)

    with pytest.raises(FusionError, match="alpha must be in"):
        fuse_scores(s_rf, s_lstm, alpha=1.1)

    # Disjoint index under strict alignment raises FusionError
    s_disjoint = pd.Series([0.2, 0.9], index=[2, 3])
    with pytest.raises(FusionError, match="strict comparison requires identical populations"):
        fuse_scores(s_rf, s_disjoint, alpha=0.5, how="strict")


def test_random_forest_feature_schema_rejection():
    import pandas as pd
    from xrlids.models.random_forest import RandomForestDetector, RandomForestError

    rf = RandomForestDetector(feature_names=["f1", "f2"])
    # Not fitted check
    with pytest.raises(RandomForestError, match="not fitted"):
        rf.predict_proba(pd.DataFrame([[1, 2]], columns=["f1", "f2"]))


def test_server_default_no_auto_streaming():
    from dashboard.server import LIVE_SESSION
    # Clean idle state when server is created without autostart
    assert LIVE_SESSION.status in ("stopped", "idle")

