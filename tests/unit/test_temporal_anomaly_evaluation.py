"""Unit tests for temporal anomaly evaluation functions and threshold sweeping."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pytest

from scripts.phase1.evaluate_temporal_anomaly_baseline import (
    _build_real_markdown_report,
    compute_metrics_at_threshold,
    compute_threshold_sweep,
    verify_dataset_prerequisites,
)


def test_compute_metrics_at_threshold_perfect():
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])

    m = compute_metrics_at_threshold(y_true, scores, threshold=0.5)
    assert m["threshold"] == 0.5
    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["fpr"] == 0.0
    assert m["specificity"] == 1.0
    assert m["roc_auc"] == 1.0
    assert m["pr_auc"] == 1.0
    assert m["tp"] == 4
    assert m["fp"] == 0
    assert m["tn"] == 4
    assert m["fn"] == 0


def test_compute_metrics_at_threshold_all_negative():
    y_true = np.array([0, 0, 0, 0, 0])
    scores = np.array([0.1, 0.2, 0.3, 0.7, 0.8])

    m = compute_metrics_at_threshold(y_true, scores, threshold=0.5)
    assert m["accuracy"] == 0.6
    assert m["tn"] == 3
    assert m["fp"] == 2
    assert m["tp"] == 0
    assert m["fn"] == 0
    assert m["specificity"] == 0.6
    assert m["fpr"] == 0.4


def test_compute_threshold_sweep_monotonic_properties():
    y_true = np.array([0] * 50 + [1] * 50)
    rng = np.random.default_rng(42)
    scores = np.concatenate([
        rng.uniform(0.1, 0.6, size=50),
        rng.uniform(0.4, 0.9, size=50),
    ])

    sweep = compute_threshold_sweep(y_true, scores)
    assert len(sweep) == 9
    expected_thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    for row, exp_t in zip(sweep, expected_thresholds):
        assert row["threshold"] == exp_t

    # As threshold increases:
    # - Recall should be non-increasing
    # - FPR should be non-increasing
    # - Specificity should be non-decreasing
    recalls = [r["recall"] for r in sweep]
    fprs = [r["fpr"] for r in sweep]
    specificities = [r["specificity"] for r in sweep]

    for i in range(len(sweep) - 1):
        assert recalls[i] >= recalls[i + 1]
        assert fprs[i] >= fprs[i + 1]
        assert specificities[i] <= specificities[i + 1]


def test_verify_dataset_prerequisites_fails_loudly_on_missing(tmp_path):
    with patch("scripts.phase1.evaluate_temporal_anomaly_baseline.RAW_DIR", tmp_path / "nonexistent"):
        with pytest.raises(FileNotFoundError, match="CRITICAL REPRODUCIBILITY ERROR"):
            verify_dataset_prerequisites()


def test_build_real_markdown_report():
    sample_res = {
        "benchmark_id": "EXP-TEST-001",
        "dataset": "cse_cic_ids2018",
        "data_source": "PHYSICAL_RAW_CSV_FILES_ON_DISK",
        "timestamp": "2026-10-28T00:00:00Z",
        "sample_counts": {
            "real_train_benign_flows": 1000,
            "real_test_flows_evaluated": 2000,
        },
        "overall_metrics": {
            "unsupervised_isolation_forest": {
                "accuracy": 0.60,
                "precision": 0.55,
                "recall": 0.50,
                "f1": 0.52,
                "fpr": 0.30,
                "specificity": 0.70,
                "roc_auc": 0.65,
                "pr_auc": 0.58,
            },
            "supervised_random_forest": {
                "accuracy": 0.50,
                "precision": 0.20,
                "recall": 0.05,
                "f1": 0.08,
                "fpr": 0.02,
                "specificity": 0.98,
                "roc_auc": 0.50,
                "pr_auc": 0.25,
            },
        },
        "threshold_sweeps": {
            "unsupervised_isolation_forest": [
                {
                    "threshold": 0.50,
                    "accuracy": 0.60,
                    "precision": 0.55,
                    "recall": 0.50,
                    "f1": 0.52,
                    "fpr": 0.30,
                    "specificity": 0.70,
                }
            ]
        },
        "per_family_metrics": {
            "BENIGN": {
                "support": 1000,
                "rf_specificity": 0.98,
                "anomaly_specificity": 0.70,
                "anomaly_fpr": 0.30,
            },
            "BOT": {
                "support": 1000,
                "rf_detection_rate": 0.0004,
                "anomaly_detection_rate": 0.50,
                "anomaly_miss_rate": 0.50,
                "anomaly_family_roc_auc": 0.5343,
            },
        },
    }

    report = _build_real_markdown_report(sample_res)
    assert "# Temporal Generalization: Empirical Anomaly Baseline" in report
    assert "EXP-TEST-001" in report
    assert "0.04%" in report  # 0.0004 * 100 = 0.04%
    assert "50.00%" in report
    assert "30.00% (FPR)" in report
    assert "0.5343" in report
