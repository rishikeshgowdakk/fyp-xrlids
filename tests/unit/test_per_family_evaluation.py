"""Unit tests for Per-Attack-Family Evaluation and Stratified Summaries (Tasks 10, 11)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.evaluation.error_analysis import (
    compute_per_family_metrics,
    compute_stratified_dataset_summary,
)


def test_compute_per_family_metrics():
    # 6 samples: 3 Benign, 2 DoS, 1 PortScan
    y_true = np.array([0, 0, 0, 1, 1, 1])
    # Predictions:
    # Benign: [0.1, 0.2, 0.9] -> 2 TN, 1 FP
    # DoS: [0.8, 0.7] -> 2 TP, 0 FN (100% recall)
    # PortScan: [0.3] -> 0 TP, 1 FN (0% recall)
    y_score = np.array([0.1, 0.2, 0.9, 0.8, 0.7, 0.3])
    families = np.array(["BENIGN", "BENIGN", "BENIGN", "DoS", "DoS", "PortScan"])

    res = compute_per_family_metrics(y_true, y_score, families, threshold=0.5)

    assert res["total_evaluated_rows"] == 6
    assert res["total_attack_families"] == 2
    bdown = res["family_breakdown"]

    assert "BENIGN" in bdown
    assert bdown["BENIGN"]["support"] == 3
    assert bdown["BENIGN"]["false_positives"] == 1
    assert bdown["BENIGN"]["correct"] == 2

    assert "DoS" in bdown
    assert bdown["DoS"]["support"] == 2
    assert bdown["DoS"]["detection_rate"] == 1.0
    assert bdown["DoS"]["false_negatives"] == 0

    assert "PortScan" in bdown
    assert bdown["PortScan"]["support"] == 1
    assert bdown["PortScan"]["detection_rate"] == 0.0
    assert bdown["PortScan"]["false_negatives"] == 1


def test_compute_stratified_dataset_summary():
    prov = pd.DataFrame({
        "label_family": ["BENIGN", "BENIGN", "DoS", "PortScan", "BENIGN"],
        "source_file": ["Monday.csv", "Monday.csv", "Wednesday.csv", "Friday.csv", "Friday.csv"],
    })
    labels = pd.Series([0, 0, 1, 1, 0])

    summary = compute_stratified_dataset_summary(prov, labels)

    assert summary["total_rows"] == 5
    assert summary["benign_count"] == 3
    assert summary["attack_count"] == 2
    assert summary["number_of_attack_families"] == 2
    assert summary["distinct_source_files"] == 3
