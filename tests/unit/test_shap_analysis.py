"""Unit tests for SHAP explainability module."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.explainability.shap_analysis import compute_rf_shap_explanations
from xrlids.models.random_forest import RandomForestDetector


def test_compute_rf_shap_explanations_basic():
    rng = np.random.default_rng(42)
    # Synthetic dataset where f1 is strongly correlated with class
    n = 100
    f1 = rng.normal(size=n)
    f2 = rng.normal(size=n)
    y = pd.Series((f1 > 0).astype(int))
    X = pd.DataFrame({"f1": f1, "f2": f2})

    rf = RandomForestDetector(params={"n_estimators": 10, "random_state": 42}).fit(X, y)

    res = compute_rf_shap_explanations(
        rf,
        X_background=X.iloc[:30],
        X_explain=X.iloc[30:50],
        y_explain=y.iloc[30:50],
        feature_names=["f1", "f2"],
        seed=42,
    )

    assert res["status"] == "COMPUTED"
    assert len(res["global_importance"]) == 2
    # f1 should have higher mean absolute SHAP than random noise f2
    assert res["global_importance"][0]["feature"] == "f1"
    assert "scientific_caveats" in res
    assert "causality" in res["scientific_caveats"]
    assert len(res["local_explanations"]) > 0
