"""Unit tests for the end-to-end flagship engine (previously untested).

Covers the two silent-failure modes found in review:
1. ``explain=True`` returned an empty attribution dict because the SHAP output
   layout was mis-indexed and the exception was swallowed at DEBUG level.
2. ``lstm_score`` silently equalled ``rf_score`` before the 5-flow window filled,
   with nothing in the output indicating the substitution.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.features.definitions import R10_FEATURES
from xrlids.flagship import FlagshipXRLIDS, _class1_attributions
from xrlids.models.random_forest import RandomForestDetector


def _toy_detector() -> RandomForestDetector:
    """Small but genuinely fitted Random Forest over the R10 contract."""
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.normal(size=(300, len(R10_FEATURES))), columns=list(R10_FEATURES))
    y = pd.Series((X["syn_count"] + X["flow_bytes_per_s"] > 0).astype(int))
    return RandomForestDetector(
        params={"n_estimators": 8, "max_depth": 3, "random_state": 0},
        feature_names=list(R10_FEATURES),
    ).fit(X, y)


def _single_flow() -> dict[str, float]:
    return {
        "flow_duration_ms": 3250.0,
        "flow_packets_per_s": 0.615385,
        "flow_bytes_per_s": 219.076923,
        "packet_length_mean": 356.0,
        "packet_length_std": 0.0,
        "syn_count": 1.0,
        "ack_count": 1.0,
        "rst_count": 1.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 1.0,
    }


@pytest.mark.parametrize(
    "shap_values",
    [
        # sklearn binary classifier -> (n_samples, n_features, n_classes)
        np.zeros((1, len(R10_FEATURES), 2)),
        # list of per-class arrays -> [class_0, class_1]
        [np.zeros((1, len(R10_FEATURES))), np.ones((1, len(R10_FEATURES)))],
        # single class already selected -> (n_samples, n_features)
        np.full((1, len(R10_FEATURES)), 0.5),
        # single sample already flattened -> (n_features,)
        np.full((len(R10_FEATURES),), 0.5),
    ],
    ids=["3d", "class-list", "2d", "1d"],
)
def test_class1_attributions_handles_every_shap_layout(shap_values):
    vals = _class1_attributions(shap_values, len(R10_FEATURES))
    assert len(vals) == len(R10_FEATURES)
    assert all(isinstance(v, float) for v in vals)


def test_class1_attributions_rejects_wrong_feature_count():
    with pytest.raises(ValueError):
        _class1_attributions(np.zeros((1, 3, 2)), len(R10_FEATURES))


def test_explain_returns_non_empty_attributions():
    """Regression test for the swallowed SHAP exception."""
    engine = FlagshipXRLIDS(rf_detector=_toy_detector(), feature_columns=R10_FEATURES)
    decision = engine.process_flow(_single_flow(), explain=True)

    assert set(decision.shap_attributions) == set(R10_FEATURES)
    assert all(np.isfinite(v) for v in decision.shap_attributions.values())


def test_lstm_fallback_is_reported_not_hidden():
    """Without an LSTM the score is an RF copy, and that must be visible."""
    engine = FlagshipXRLIDS(rf_detector=_toy_detector(), feature_columns=R10_FEATURES)
    decision = engine.process_flow(_single_flow())

    assert decision.lstm_score_source == "rf_fallback"
    assert decision.lstm_score == decision.rf_score
    assert decision.to_dict()["lstm_score_source"] == "rf_fallback"
