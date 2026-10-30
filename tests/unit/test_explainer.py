"""Unit tests for the unified TreeSHAPExplainer."""

from pathlib import Path
import numpy as np
import pytest

from xrlids.explainability.explainer import ExplanationResult, TreeSHAPExplainer
from xrlids.models.random_forest import RandomForestDetector
from xrlids.models.xgboost_detector import XGBoostDetector

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def sample_r10_flow():
    return {
        "flow_duration_ms": 1250.0,
        "flow_packets_per_s": 80.5,
        "flow_bytes_per_s": 15400.0,
        "packet_length_mean": 191.3,
        "packet_length_std": 84.2,
        "syn_count": 2.0,
        "ack_count": 4.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }


def test_explainer_on_random_forest(sample_r10_flow):
    import joblib
    rf_path = REPO_ROOT / "models" / "rf" / "random_forest_cicids2017.joblib"
    if not rf_path.exists():
        pytest.skip(f"RF model not found at {rf_path}")

    detector = joblib.load(rf_path)
    explainer = TreeSHAPExplainer(detector)

    result = explainer.explain_flow(sample_r10_flow)
    assert isinstance(result, ExplanationResult)
    assert result.model_type == "rf"
    assert len(result.top_features) == 10
    assert len(result.attributions) == 10
    assert result.explanation_time_ms > 0

    # Verify descending absolute magnitude sorting
    mags = [abs(f["shap_attribution"]) for f in result.top_features]
    assert mags == sorted(mags, reverse=True)

    # Verify direction labels
    for f in result.top_features:
        attrib = f["shap_attribution"]
        if attrib > 1e-5:
            assert f["direction"] == "INCREASES_THREAT"
        elif attrib < -1e-5:
            assert f["direction"] == "DECREASES_THREAT"
        else:
            assert f["direction"] == "NEUTRAL"


def test_explainer_on_xgboost(sample_r10_flow):
    xgb_path = REPO_ROOT / "models" / "xgboost" / "xgboost_cicids2017.json"
    if not xgb_path.exists():
        pytest.skip(f"XGBoost model not found at {xgb_path}")

    detector = XGBoostDetector.load(xgb_path)
    explainer = TreeSHAPExplainer(detector)

    result = explainer.explain_flow(sample_r10_flow)
    assert isinstance(result, ExplanationResult)
    assert result.model_type == "xgboost"
    assert len(result.top_features) == 10
    assert len(result.attributions) == 10

    mags = [abs(f["shap_attribution"]) for f in result.top_features]
    assert mags == sorted(mags, reverse=True)
