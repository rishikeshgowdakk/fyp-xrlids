"""Model tests: RF, LSTM and fusion on tiny deterministic fixtures."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.models.fusion import FusionError, fuse_scores
from xrlids.models.lstm import (
    LSTMDetector,
    SequenceError,
    assert_no_boundary_crossing,
    build_sequences,
)
from xrlids.models.random_forest import RandomForestDetector, RandomForestError


def _xy(n=120, seed=0):
    rng = np.random.default_rng(seed)
    X = pd.DataFrame(rng.normal(size=(n, 4)), columns=["a", "b", "c", "d"])
    y = pd.Series((X["a"] + X["b"] > 0).astype(int))
    return X, y


# --------------------------------------------------------------------- RF
def test_rf_trains_and_scores_continuously():
    X, y = _xy()
    rf = RandomForestDetector(params={"n_estimators": 20}).fit(X, y)
    scores = rf.predict_proba(X)
    assert scores.shape == (len(X),)
    assert scores.min() >= 0.0 and scores.max() <= 1.0
    assert not np.all(np.isin(scores, [0.0, 1.0]))  # continuous, not hard labels


def test_rf_rejects_feature_order_mismatch():
    X, y = _xy()
    rf = RandomForestDetector(params={"n_estimators": 10}).fit(X, y)
    with pytest.raises(RandomForestError, match="order"):
        rf.predict_proba(X[["b", "a", "c", "d"]])


def test_rf_rejects_single_class():
    X, _ = _xy()
    with pytest.raises(RandomForestError):
        RandomForestDetector().fit(X, pd.Series(np.zeros(len(X), dtype=int)))


def test_rf_feature_importances_sum_to_one():
    X, y = _xy()
    rf = RandomForestDetector(params={"n_estimators": 10}).fit(X, y)
    assert rf.feature_importances()["importance"].sum() == pytest.approx(1.0)


# ------------------------------------------------------------------ LSTM
def test_sequences_never_cross_split_boundaries():
    X, y = _xy(60)
    train = build_sequences(X.iloc[:30], y.iloc[:30], split="train", seq_len=5)
    test = build_sequences(X.iloc[30:], y.iloc[30:], split="test", seq_len=5)
    # must not raise: sequences stay inside their own split
    assert_no_boundary_crossing([train, test], {"train": 30, "test": 30})
    assert train.X.shape[1] == 5
    assert len(train) == 26  # 30 - 5 + 1


def test_sequence_boundary_violation_is_detected():
    X, y = _xy(20)
    seqs = build_sequences(X, y, split="train", seq_len=5)
    with pytest.raises(SequenceError):
        # claim the split is smaller than it really is -> sequences appear to overrun
        assert_no_boundary_crossing([seqs], {"train": 10})


def test_sequence_label_rules():
    X, y = _xy(10)
    last = build_sequences(X, y, split="s", seq_len=4, label_rule="last")
    anyl = build_sequences(X, y, split="s", seq_len=4, label_rule="any")
    assert anyl.y.sum() >= last.y.sum()


def test_lstm_trains_and_predicts():
    X, y = _xy(150)
    tr = build_sequences(X.iloc[:100], y.iloc[:100], split="train", seq_len=4)
    va = build_sequences(X.iloc[100:], y.iloc[100:], split="validation", seq_len=4)
    det = LSTMDetector(
        params={"epochs": 2, "patience": 2, "batch_size": 32, "hidden_size": 8, "num_layers": 1, "dropout": 0.0},
        feature_names=list(X.columns),
        seq_len=4,
        seed=1,
    ).fit(tr, va)
    scores = det.predict_proba(va)
    assert scores.shape == (len(va),)
    assert np.all((scores >= 0) & (scores <= 1))
    assert det.history  # training history recorded


# ----------------------------------------------------------------- fusion
def test_fusion_alignment_and_weighting():
    rf = pd.Series([0.2, 0.8, 0.6], index=[0, 1, 2])
    lstm = pd.Series([0.4, 0.6, 0.5], index=[0, 1, 2])
    out = fuse_scores(rf, lstm, alpha=0.5)
    assert out.alignment["aligned_rows"] == 3
    assert np.allclose(out.scores, [0.3, 0.7, 0.55])


def test_fusion_reports_dropped_rows_when_populations_differ():
    rf = pd.Series([0.2, 0.8, 0.6], index=[0, 1, 2])
    lstm = pd.Series([0.4, 0.6], index=[0, 1])
    out = fuse_scores(rf, lstm)
    assert out.alignment["aligned_rows"] == 2
    assert out.alignment["dropped_from_rf"] == 1
    assert out.alignment["population_warning"] is not None


def test_fusion_alpha_bounds_enforced():
    rf = pd.Series([0.2], index=[0])
    with pytest.raises(FusionError):
        fuse_scores(rf, rf, alpha=1.5)


def test_tune_fusion_alpha_selects_best_weight_on_validation():
    from xrlids.models.fusion import tune_fusion_alpha

    y = pd.Series([0, 1, 1, 0], index=[0, 1, 2, 3])
    # RF gets sample 1 right, misses sample 2
    rf = pd.Series([0.2, 0.8, 0.3, 0.2], index=[0, 1, 2, 3])
    # LSTM gets sample 2 right, misses sample 1
    lstm = pd.Series([0.1, 0.3, 0.8, 0.2], index=[0, 1, 2, 3])

    res = tune_fusion_alpha(rf, lstm, y, metric="f1")
    # alpha=0.5 fuses them to [0.15, 0.55, 0.55, 0.20], classifying all 4 correctly!
    assert res["best_alpha"] == 0.5
    assert res["best_metric_value"] == pytest.approx(1.0)


