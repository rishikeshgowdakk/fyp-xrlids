"""Unit tests for the XGBoost detector wrapper."""

import numpy as np
import pandas as pd
import pytest

from xrlids.models.xgboost_detector import XGBoostDetector, XGBoostError


@pytest.fixture
def sample_data():
    np.random.seed(42)
    n = 200
    features = [f"f{i}" for i in range(10)]
    X = pd.DataFrame(np.random.randn(n, 10), columns=features)
    y = pd.Series(np.random.choice([0, 1], size=n, p=[0.7, 0.3]))
    return X, y, features


def test_xgboost_fit_and_predict(sample_data):
    X, y, features = sample_data
    detector = XGBoostDetector(params={"n_estimators": 10, "max_depth": 3})
    detector.fit(X, y)

    assert detector.model is not None
    assert detector.n_train_rows == len(X)
    assert detector.feature_names == features

    # Test predict_proba
    probas = detector.predict_proba(X)
    assert isinstance(probas, np.ndarray)
    assert len(probas) == len(X)
    assert np.all((probas >= 0.0) & (probas <= 1.0))

    # Test predict with threshold
    preds_05 = detector.predict(X, threshold=0.5)
    assert np.array_equal(preds_05, (probas >= 0.5).astype(int))

    preds_08 = detector.predict(X, threshold=0.8)
    assert np.array_equal(preds_08, (probas >= 0.8).astype(int))


def test_xgboost_numpy_input():
    np.random.seed(42)
    X = np.random.randn(100, 5)
    y = np.random.choice([0, 1], size=100)
    names = [f"feat_{i}" for i in range(5)]

    detector = XGBoostDetector(params={"n_estimators": 5, "max_depth": 2})
    detector.fit(X, y, feature_names=names)

    assert detector.feature_names == names
    probas = detector.predict_proba(X)
    assert len(probas) == 100


def test_xgboost_validation_errors(sample_data):
    X, y, features = sample_data
    detector = XGBoostDetector()

    # Unfitted error
    with pytest.raises(XGBoostError, match="not fitted"):
        detector.predict_proba(X)

    # Length mismatch
    with pytest.raises(XGBoostError, match="different lengths"):
        detector.fit(X, y.iloc[:-1])

    # Single class
    with pytest.raises(XGBoostError, match="single class"):
        detector.fit(X, pd.Series([0] * len(X)))

    # Fit once
    detector.fit(X, y)
    with pytest.raises(XGBoostError, match="already fitted"):
        detector.fit(X, y)

    # Feature mismatch
    X_bad = X.drop(columns=[features[0]])
    with pytest.raises(XGBoostError, match="mismatch"):
        detector.predict_proba(X_bad)


def test_xgboost_feature_importances(sample_data):
    X, y, features = sample_data
    detector = XGBoostDetector(params={"n_estimators": 10, "max_depth": 3})
    detector.fit(X, y)

    fi = detector.feature_importances()
    assert isinstance(fi, pd.DataFrame)
    assert list(fi.columns) == ["feature", "importance"]
    assert len(fi) == len(features)
    assert fi["importance"].is_monotonic_decreasing


def test_xgboost_save_and_load(sample_data, tmp_path):
    X, y, features = sample_data
    detector = XGBoostDetector(params={"n_estimators": 10, "max_depth": 3})
    detector.fit(X, y)

    preds_before = detector.predict_proba(X)

    # Save to directory
    save_dir = tmp_path / "model_dir"
    detector.save(save_dir)

    # Load from directory
    loaded = XGBoostDetector.load(save_dir)
    preds_after = loaded.predict_proba(X)

    assert np.allclose(preds_before, preds_after, atol=1e-5)
    assert loaded.feature_names == features
    assert loaded.n_train_rows == len(X)

    # Save to specific file path
    file_path = tmp_path / "custom" / "xgb.json"
    detector.save(file_path)
    loaded_file = XGBoostDetector.load(file_path)
    preds_file = loaded_file.predict_proba(X)
    assert np.allclose(preds_before, preds_file, atol=1e-5)
