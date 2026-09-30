"""Unit tests for error analysis and model disagreement modules."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.evaluation.error_analysis import (
    analyze_model_disagreements,
    compute_error_analysis,
)


def test_compute_error_analysis_identifies_fps_and_fns():
    # 6 samples: 3 benign (0), 3 attack (1)
    y_true = np.array([0, 0, 0, 1, 1, 1])
    # Predicted scores:
    # 0 -> 0.1 (TN)
    # 1 -> 0.2 (TN)
    # 2 -> 0.8 (FP! benign predicted as attack)
    # 3 -> 0.3 (FN! attack predicted as benign)
    # 4 -> 0.9 (TP)
    # 5 -> 0.7 (TP)
    y_score = np.array([0.1, 0.2, 0.8, 0.3, 0.9, 0.7])
    df = pd.DataFrame({"f1": [1, 2, 3, 4, 5, 6]})

    result = compute_error_analysis(y_true, y_score, threshold=0.5, features_df=df)

    assert result["confusion"]["tp"] == 2
    assert result["confusion"]["tn"] == 2
    assert result["confusion"]["fp"] == 1
    assert result["confusion"]["fn"] == 1

    # Worst FN should be index 3 (score 0.3)
    worst_fn = result["difficult_samples"]["worst_false_negatives"]
    assert len(worst_fn) == 1
    assert worst_fn[0]["index"] == 3
    assert worst_fn[0]["predicted_score"] == pytest.approx(0.3)
    assert worst_fn[0]["features"]["f1"] == 4

    # Worst FP should be index 2 (score 0.8)
    worst_fp = result["difficult_samples"]["worst_false_positives"]
    assert len(worst_fp) == 1
    assert worst_fp[0]["index"] == 2
    assert worst_fp[0]["predicted_score"] == pytest.approx(0.8)


def test_compute_error_analysis_duplicate_breakdown():
    y_true = np.array([0, 0, 1, 1])
    y_score = np.array([0.1, 0.8, 0.2, 0.9])
    duplicate_mask = np.array([False, True, False, True])

    result = compute_error_analysis(y_true, y_score, threshold=0.5, duplicate_mask=duplicate_mask)
    dup_res = result["duplicate_subset_analysis"]
    assert dup_res is not None
    assert dup_res["evaluated"] is True
    assert dup_res["duplicate_rows"] == 2
    assert dup_res["unique_rows"] == 2
    assert "accuracy" in dup_res["duplicate_subset_metrics"]


def test_analyze_model_disagreements():
    y_true = np.array([0, 1, 1, 0])
    rf_score = np.array([0.2, 0.8, 0.3, 0.7])  # TN, TP, FN, FP
    lstm_score = np.array([0.1, 0.4, 0.9, 0.2])  # TN, FN, TP, TN
    fusion_score = 0.5 * rf_score + 0.5 * lstm_score  # [0.15, 0.6, 0.6, 0.45] -> TN, TP, TP, TN

    dis = analyze_model_disagreements(y_true, rf_score, lstm_score, fusion_score=fusion_score, threshold=0.5)

    # Disagreements on sample 1 (RF 0.8 vs LSTM 0.4), sample 2 (RF 0.3 vs LSTM 0.9), sample 3 (RF 0.7 vs LSTM 0.2)
    assert dis["disagreement_count"] == 3
    assert dis["aligned_population_size"] == 4

    # Fusion role:
    fus = dis["fusion_analysis"]
    assert fus is not None
    # For sample 1 (y=1): RF=1, LSTM=0, Fusion=0.6 -> 1 (rescue!)
    # For sample 2 (y=1): RF=0, LSTM=1, Fusion=0.6 -> 1 (rescue!)
    # For sample 3 (y=0): RF=1, LSTM=0, Fusion=0.45 -> 0 (rescue!)
    assert fus["fusion_rescues_when_one_model_failed"] == 3
