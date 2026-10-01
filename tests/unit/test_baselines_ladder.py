"""Unit tests for Baseline Ladder detectors (Task 8)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.models.baselines import (
    DecisionTreeDetector,
    LogisticRegressionDetector,
    MajorityClassDetector,
)


@pytest.fixture
def synthetic_data():
    rng = np.random.default_rng(42)
    X = pd.DataFrame({
        "feat1": rng.normal(0, 1, 100),
        "feat2": rng.normal(2, 1, 100),
    })
    # y=1 when feat1 + feat2 > 2
    y = pd.Series(((X["feat1"] + X["feat2"]) > 2).astype(int))
    return X, y


def test_majority_class_detector(synthetic_data):
    X, y = synthetic_data
    detector = MajorityClassDetector().fit(X, y)
    probs = detector.predict_proba(X)
    preds = detector.predict(X)

    assert len(probs) == len(X)
    assert len(preds) == len(X)
    assert np.all(preds == detector.majority_class)
    assert np.allclose(probs, detector.prior_probability)
    assert detector.config()["model_type"] == "majority_class"


def test_logistic_regression_detector(synthetic_data, tmp_path):
    X, y = synthetic_data
    detector = LogisticRegressionDetector(seed=42).fit(X, y)
    probs = detector.predict_proba(X)
    preds = detector.predict(X)

    assert len(probs) == len(X)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.all((preds == 0) | (preds == 1))

    # Persistence
    save_path = detector.save(tmp_path)
    loaded = LogisticRegressionDetector.load(save_path)
    np.testing.assert_allclose(probs, loaded.predict_proba(X))


def test_decision_tree_detector(synthetic_data, tmp_path):
    X, y = synthetic_data
    detector = DecisionTreeDetector(seed=42).fit(X, y)
    probs = detector.predict_proba(X)
    preds = detector.predict(X)

    assert len(probs) == len(X)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.all((preds == 0) | (preds == 1))

    # Persistence
    save_path = detector.save(tmp_path)
    loaded = DecisionTreeDetector.load(save_path)
    np.testing.assert_allclose(probs, loaded.predict_proba(X))
