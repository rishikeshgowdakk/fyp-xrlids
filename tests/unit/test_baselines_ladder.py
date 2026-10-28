"""Unit tests for Baseline Ladder detectors (Task 8)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.models.baselines import (
    DecisionTreeDetector,
    IsolationForestDetector,
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


def test_isolation_forest_detector(tmp_path):
    rng = np.random.default_rng(42)
    X_benign = pd.DataFrame({
        "feat1": rng.normal(0, 1, 200),
        "feat2": rng.normal(0, 1, 200),
    })
    y_benign = pd.Series(np.zeros(200, dtype=int))

    X_anom = pd.DataFrame({
        "feat1": rng.normal(5, 1, 50),
        "feat2": rng.normal(5, 1, 50),
    })
    y_anom = pd.Series(np.ones(50, dtype=int))

    X_all = pd.concat([X_benign, X_anom], ignore_index=True)
    y_all = pd.concat([y_benign, y_anom], ignore_index=True)

    # 1. Fit on benign only via y filter
    detector = IsolationForestDetector(seed=42).fit(X_all, y_all)
    assert detector.fitted

    probs = detector.predict_proba(X_all)
    preds = detector.predict(X_all, threshold=0.5)

    assert len(probs) == len(X_all)
    assert np.all((probs >= 0.0) & (probs <= 1.0))
    assert np.all((preds == 0) | (preds == 1))

    # Anomalies should have significantly higher scores than benign
    benign_scores = probs[:200]
    anom_scores = probs[200:]
    assert np.mean(anom_scores) > np.mean(benign_scores)
    assert np.median(anom_scores) > np.median(benign_scores)

    # Persistence
    save_path = detector.save(tmp_path)
    loaded = IsolationForestDetector.load(save_path)
    np.testing.assert_allclose(probs, loaded.predict_proba(X_all))
    assert loaded.config()["model_type"] == "isolation_forest"

