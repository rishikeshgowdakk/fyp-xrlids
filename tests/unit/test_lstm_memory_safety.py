"""Unit tests for memory-bounded LSTM implementation (Task 13)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.models.lstm import (
    LSTMDetector,
    SequenceArray,
    SequenceError,
    SequenceSet,
    assert_no_boundary_crossing,
    build_sequences,
)
from xrlids.utils.profiler import get_rss_mib


def test_sequence_generation_shapes_and_values():
    """Verify shapes and that SequenceArray yields exact values matching dense 3D array."""
    n_rows, n_feat, seq_len = 50, 4, 5
    features = pd.DataFrame(np.arange(n_rows * n_feat, dtype=float).reshape(n_rows, n_feat))
    labels = pd.Series((np.arange(n_rows) % 3 == 0).astype(int))

    seq_set = build_sequences(features, labels, split="train", seq_len=seq_len, stride=1)
    assert len(seq_set) == n_rows - seq_len + 1
    assert seq_set.X.shape == (len(seq_set), seq_len, n_feat)
    assert seq_set.X.shape[1] == seq_len
    assert seq_set.n_features == n_feat

    # Check that individual sequence indexing matches exact slice
    for i in range(min(5, len(seq_set))):
        expected_window = features.iloc[i : i + seq_len].to_numpy(dtype=np.float32)
        actual_window = seq_set.X[i]
        np.testing.assert_allclose(actual_window, expected_window)

    # Check np.asarray(seq_set.X) matches 3D stack
    arr_3d = np.asarray(seq_set.X)
    assert arr_3d.shape == (len(seq_set), seq_len, n_feat)


def test_group_boundary_crossing_prevention():
    """Verify sequences never cross session/group boundaries when groups are provided."""
    n_rows = 20
    features = pd.DataFrame(np.random.randn(n_rows, 3))
    labels = pd.Series(np.zeros(n_rows, dtype=int))
    # Groups: 0..9 belong to session 1, 10..19 belong to session 2
    groups = pd.Series([1] * 10 + [2] * 10)

    seq_len = 4
    seq_set = build_sequences(features, labels, split="train", seq_len=seq_len, groups=groups)

    # In session 1 (len 10): 10 - 4 + 1 = 7 sequences (origins 0..6)
    # In session 2 (len 10): 10 - 4 + 1 = 7 sequences (origins 10..16)
    # Boundary sequences (origins 7, 8, 9) must be skipped!
    assert len(seq_set) == 14
    for orig in seq_set.origins:
        assert orig not in [7, 8, 9]


def test_predict_proba_two_class_sums_to_one():
    """Verify predict_proba with two_class=True produces valid probabilities that sum to 1."""
    n_rows = 80
    features = pd.DataFrame(np.random.randn(n_rows, 4))
    labels = pd.Series(np.random.randint(0, 2, size=n_rows))

    tr = build_sequences(features.iloc[:50], labels.iloc[:50], split="train", seq_len=4)
    va = build_sequences(features.iloc[50:], labels.iloc[50:], split="validation", seq_len=4)

    det = LSTMDetector(
        params={"epochs": 2, "batch_size": 16, "hidden_size": 8, "num_layers": 1, "dropout": 0.0},
        seq_len=4,
        seed=42,
    ).fit(tr, va)

    probs_2d = det.predict_proba(va, two_class=True)
    assert probs_2d.shape == (len(va), 2)
    assert np.all((probs_2d >= 0.0) & (probs_2d <= 1.0))
    np.testing.assert_allclose(probs_2d.sum(axis=1), np.ones(len(va)), rtol=1e-5)


def test_lstm_memory_bounded_training():
    """Verify peak memory during training stays within reasonable bounds and mini-batching works."""
    start_rss = get_rss_mib()
    # Create moderate dataset (e.g. 2000 rows, 10 features)
    n_rows = 2000
    features = pd.DataFrame(np.random.randn(n_rows, 10))
    labels = pd.Series(np.random.randint(0, 2, size=n_rows))

    tr = build_sequences(features.iloc[:1600], labels.iloc[:1600], split="train", seq_len=5)
    va = build_sequences(features.iloc[1600:], labels.iloc[1600:], split="val", seq_len=5)

    det = LSTMDetector(
        params={"epochs": 3, "batch_size": 64, "hidden_size": 16, "num_layers": 1, "dropout": 0.0},
        seq_len=5,
        seed=42,
    ).fit(tr, va)

    end_rss = get_rss_mib()
    delta_mb = end_rss - start_rss
    # Training moderate dataset on CPU should not balloon RSS (< 500 MiB delta)
    assert delta_mb < 500.0


def test_lstm_save_and_load(tmp_path):
    """Verify LSTMDetector save and load reconstruct identical model predictions."""
    n_rows = 100
    features = pd.DataFrame(np.random.randn(n_rows, 4), columns=["f1", "f2", "f3", "f4"])
    labels = pd.Series(np.random.randint(0, 2, size=n_rows))

    tr = build_sequences(features.iloc[:70], labels.iloc[:70], split="train", seq_len=4)
    va = build_sequences(features.iloc[70:], labels.iloc[70:], split="validation", seq_len=4)

    det = LSTMDetector(
        params={"epochs": 2, "batch_size": 16, "hidden_size": 8, "num_layers": 1, "dropout": 0.0},
        feature_names=["f1", "f2", "f3", "f4"],
        seq_len=4,
        seed=42,
    ).fit(tr, va)

    preds_before = det.predict_proba(va)
    save_path = det.save(tmp_path)
    assert save_path.is_file()

    loaded = LSTMDetector.load(tmp_path)
    assert loaded.seq_len == det.seq_len
    assert loaded.feature_names == det.feature_names
    preds_after = loaded.predict_proba(va)

    np.testing.assert_allclose(preds_before, preds_after, rtol=1e-5)


def test_build_sequences_session_column_alias():
    """Verify session_column argument behaves identically to groups argument."""
    n_rows = 20
    features = pd.DataFrame(np.random.randn(n_rows, 3))
    labels = pd.Series(np.zeros(n_rows, dtype=int))
    sessions = pd.Series([1] * 10 + [2] * 10)

    seq_set = build_sequences(features, labels, split="train", seq_len=4, session_column=sessions)
    assert len(seq_set) == 14
    for orig in seq_set.origins:
        assert orig not in [7, 8, 9]

