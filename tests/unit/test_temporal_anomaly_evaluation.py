"""Unit tests for temporal anomaly evaluation functions, threshold sweeping, and report consistency."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from scripts.phase1.evaluate_temporal_anomaly_baseline import (
    _build_real_markdown_report,
    compute_metrics_at_threshold,
    compute_threshold_sweep,
    verify_dataset_prerequisites,
)
from xrlids.models.baselines import IsolationForestDetector


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


def test_compute_metrics_at_threshold_undefined_auc_single_class():
    """Verify that single-class inputs report None for AUC rather than fabricating 0.5 or arbitrary fallbacks."""
    # 1. All-negative (y == 0): ROC-AUC and PR-AUC are mathematically undefined
    y_all_zero = np.array([0, 0, 0, 0, 0])
    scores_neg = np.array([0.1, 0.2, 0.3, 0.7, 0.8])
    m_zero = compute_metrics_at_threshold(y_all_zero, scores_neg, threshold=0.5)

    assert m_zero["roc_auc"] is None, "ROC-AUC must be None when no positive class exists"
    assert m_zero["pr_auc"] is None, "PR-AUC must be None when no positive class exists"
    assert m_zero["accuracy"] == 0.6
    assert m_zero["tn"] == 3
    assert m_zero["fp"] == 2
    assert m_zero["tp"] == 0
    assert m_zero["fn"] == 0

    # 2. All-positive (y == 1): ROC-AUC is mathematically undefined
    y_all_one = np.array([1, 1, 1, 1, 1])
    scores_pos = np.array([0.2, 0.3, 0.6, 0.8, 0.9])
    m_one = compute_metrics_at_threshold(y_all_one, scores_pos, threshold=0.5)

    assert m_one["roc_auc"] is None, "ROC-AUC must be None when no negative class exists"
    assert m_one["pr_auc"] is not None
    assert m_one["accuracy"] == 0.6
    assert m_one["tp"] == 3
    assert m_one["fn"] == 2
    assert m_one["tn"] == 0
    assert m_one["fp"] == 0


def test_compute_metrics_input_validation():
    """Verify explicit validation errors on malformed inputs."""
    # Shape mismatch
    with pytest.raises(ValueError, match="Shape mismatch"):
        compute_metrics_at_threshold(np.array([0, 1]), np.array([0.5]))

    # Empty inputs
    with pytest.raises(ValueError, match="Cannot compute metrics on empty arrays"):
        compute_metrics_at_threshold(np.array([]), np.array([]))

    # NaN in scores
    with pytest.raises(ValueError, match="Scores array contains NaN"):
        compute_metrics_at_threshold(np.array([0, 1]), np.array([0.5, np.nan]))


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


def test_date_and_report_consistency():
    """Ensure report generator derives capture dates from configuration and never cites Friday-23-02-2018."""
    sample_res = {
        "benchmark_id": "EXP-TEST-001",
        "dataset": "cse_cic_ids2018",
        "data_source": "PHYSICAL_RAW_CSV_FILES_ON_DISK",
        "timestamp": "2026-10-28T00:00:00Z",
        "evaluation_config": {
            "train_files": [
                "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
                "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
            ],
            "test_files": [
                "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
                "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
                "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
            ],
        },
        "sample_counts": {
            "real_train_benign_flows": 1000,
            "real_test_flows_evaluated": 2000,
            "test_attack_flows": 1000,
            "test_benign_flows": 1000,
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
        "drift_analysis": {
            "feature_drift": {
                "flow_duration_ms": {"train_benign_mean": 1000.0, "test_benign_mean": 3000.0, "ratio": 3.0},
                "flow_bytes_per_s": {"train_benign_mean": 500.0, "test_benign_mean": 1000.0, "ratio": 2.0},
                "rst_count": {"train_benign_mean": 0.05, "test_benign_mean": 0.25, "ratio": 5.0},
            },
            "score_distribution": {
                "train_benign": {"decision_function_mean": 0.08, "anomaly_score_mean": 0.31},
                "test_benign_holdout": {"decision_function_mean": -0.02, "anomaly_score_mean": 0.55},
                "test_bot_holdout": {"decision_function_mean": 0.06, "anomaly_score_mean": 0.35},
            },
        },
        "score_direction_verification": {
            "auc_from_anomaly_scores": 0.65,
            "auc_from_negated_decision_function": 0.65,
            "auc_from_raw_decision_function": 0.35,
        },
    }

    report = _build_real_markdown_report(sample_res)
    assert "# Temporal Generalization: Empirical Anomaly Baseline" in report
    assert "Friday-23-02-2018" not in report, "Report must NOT cite erroneous Friday-23 date"
    assert "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv" in report
    assert "0.04%" in report  # 0.0004 * 100 = 0.04%
    assert "50.00%" in report
    assert "30.00% (FPR)" in report
    assert "0.5343" in report


def test_score_orientation_and_rank_invariance():
    """Independent verification that IsolationForest anomaly_score preserves rank invariance with -decision_function."""
    rng = np.random.default_rng(42)
    X_train = rng.normal(0, 1, size=(200, 4))
    detector = IsolationForestDetector(seed=42).fit(X_train)

    X_test_normal = rng.normal(0, 0.8, size=(100, 4))
    X_test_anom = rng.normal(4.0, 1.0, size=(50, 4))
    X_test = np.vstack([X_test_normal, X_test_anom])
    y_test = np.array([0] * 100 + [1] * 50)

    raw_df = detector.decision_function(X_test)
    scores = detector.anomaly_score(X_test)

    # 1. Outliers must have higher anomaly score than normal points
    assert scores[100:].mean() > scores[:100].mean()

    # 2. Rank invariance: AUC(y, scores) must equal AUC(y, -raw_df)
    auc_scores = roc_auc_score(y_test, scores)
    auc_neg_df = roc_auc_score(y_test, -raw_df)
    assert np.isclose(auc_scores, auc_neg_df, atol=1e-5)

    # 3. Raw df without negation inverts AUC: AUC(y, raw_df) == 1 - AUC(y, scores)
    auc_raw_df = roc_auc_score(y_test, raw_df)
    assert np.isclose(auc_raw_df, 1.0 - auc_scores, atol=1e-5)


def test_json_and_report_consistency_against_disk_artifacts():
    """Verify consistency between the JSON evaluation artifact and Markdown report on disk."""
    json_path = REPO_ROOT / "results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/anomaly_baseline_evaluation.json"
    report_path = REPO_ROOT / "reports/generated/temporal_anomaly_baseline_report.md"

    if not json_path.exists() or not report_path.exists():
        pytest.skip("Disk evaluation artifacts not present; skipping disk consistency check")

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    report_text = report_path.read_text(encoding="utf-8")

    # 1. Date and file consistency
    assert "Friday-23-02-2018" not in report_text, "Markdown report must NOT reference Friday-23-02-2018"
    for test_file in data.get("evaluation_config", {}).get("test_files", []):
        assert test_file in report_text, f"Test file {test_file} must be cited in report"

    # 2. Overall metric consistency (at threshold 0.50)
    iso = data["overall_metrics"]["unsupervised_isolation_forest"]
    rf = data["overall_metrics"]["supervised_random_forest"]

    assert f"{iso['accuracy']:.4f}" in report_text
    assert f"{iso['recall']:.4f}" in report_text
    assert f"{iso['precision']:.4f}" in report_text
    assert f"{iso['f1']:.4f}" in report_text
    assert f"{iso['fpr']:.4f}" in report_text

    assert f"{rf['accuracy']:.4f}" in report_text
    assert f"{rf['recall']:.4f}" in report_text
    assert f"{rf['precision']:.4f}" in report_text
    assert f"{rf['f1']:.4f}" in report_text
    assert f"{rf['fpr']:.4f}" in report_text

    # 3. Sample count consistency
    sc = data["sample_counts"]
    assert f"{sc['real_train_benign_flows']:,}" in report_text
    assert f"{sc['real_test_flows_evaluated']:,}" in report_text

    # 4. Per-family detection rates consistency
    for fam, pf in data["per_family_metrics"].items():
        if fam != "BENIGN":
            det_pct = pf["anomaly_detection_rate"] * 100
            assert f"{det_pct:.2f}%" in report_text, f"{fam} anomaly detection percentage {det_pct:.2f}% must be in report"
