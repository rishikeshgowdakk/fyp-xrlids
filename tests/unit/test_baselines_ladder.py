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


def test_isolation_forest_unfitted_raises():
    detector = IsolationForestDetector()
    X = np.array([[1.0, 2.0]])
    with pytest.raises(RuntimeError, match="must be fitted"):
        detector.decision_function(X)
    with pytest.raises(RuntimeError, match="must be fitted"):
        detector.score_samples(X)
    with pytest.raises(RuntimeError, match="must be fitted"):
        detector.anomaly_score(X)
    with pytest.raises(RuntimeError, match="must be fitted"):
        detector.predict_proba(X)


def test_isolation_forest_score_orientation_and_monotonicity():
    rng = np.random.default_rng(42)
    # Dense cluster of normal instances
    X_train = rng.normal(loc=0.0, scale=1.0, size=(500, 4))
    detector = IsolationForestDetector(seed=42).fit(X_train)

    # Inliers (near center), Boundary (moderately far), and Extreme Outliers
    X_inliers = rng.normal(loc=0.0, scale=0.3, size=(50, 4))
    X_boundary = rng.normal(loc=1.8, scale=0.2, size=(50, 4))
    X_extreme_outliers = rng.normal(loc=10.0, scale=0.5, size=(50, 4))

    df_inliers = detector.decision_function(X_inliers)
    df_boundary = detector.decision_function(X_boundary)
    df_extreme = detector.decision_function(X_extreme_outliers)

    # 1. Decision function convention: inliers > 0, outliers < 0
    assert np.mean(df_inliers) > 0.0
    assert np.mean(df_boundary) < np.mean(df_inliers)
    assert np.mean(df_extreme) < np.mean(df_boundary)

    # 2. score_samples tracks decision_function
    ss_inliers = detector.score_samples(X_inliers)
    ss_extreme = detector.score_samples(X_extreme_outliers)
    assert np.mean(ss_inliers) > np.mean(ss_extreme)

    # 3. Anomaly scores: strictly higher for outliers, in [0, 1]
    score_inliers = detector.anomaly_score(X_inliers)
    score_boundary = detector.anomaly_score(X_boundary)
    score_extreme = detector.anomaly_score(X_extreme_outliers)

    assert np.all((score_inliers >= 0.0) & (score_inliers <= 1.0))
    assert np.all((score_boundary >= 0.0) & (score_boundary <= 1.0))
    assert np.all((score_extreme >= 0.0) & (score_extreme <= 1.0))

    assert np.mean(score_inliers) < 0.50
    assert np.mean(score_boundary) > np.mean(score_inliers)
    assert np.mean(score_extreme) > 0.90

    # 4. predict_proba equivalence
    np.testing.assert_allclose(score_inliers, detector.predict_proba(X_inliers))
    np.testing.assert_allclose(score_extreme, detector.predict_proba(X_extreme_outliers))

    # 5. Monotonic mapping: sorting by decision_function ascending exactly sorts anomaly_score descending
    combined = np.vstack([X_inliers, X_boundary, X_extreme_outliers])
    df_comb = detector.decision_function(combined)
    score_comb = detector.anomaly_score(combined)
    assert np.array_equal(np.argsort(df_comb), np.argsort(-score_comb))


