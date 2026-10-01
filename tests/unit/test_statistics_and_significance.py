"""Unit tests for Statistical Robustness and Model Comparison (Tasks 18, 19)."""

from __future__ import annotations

import numpy as np
import pytest

from xrlids.evaluation.statistics import (
    bootstrap_metric_ci,
    multi_seed_summary,
    paired_model_comparison,
)


def test_bootstrap_metric_ci():
    rng = np.random.default_rng(42)
    y_true = rng.choice([0, 1], size=200, p=[0.7, 0.3])
    # Scores strongly correlated with y_true
    y_score = np.clip(y_true * 0.8 + rng.normal(0, 0.2, 200), 0.0, 1.0)

    ci_res = bootstrap_metric_ci(y_true, y_score, metric_name="f1", n_bootstraps=200, seed=42)

    assert "point_estimate" in ci_res
    assert "ci_lower" in ci_res
    assert "ci_upper" in ci_res
    assert ci_res["ci_lower"] <= ci_res["point_estimate"] <= ci_res["ci_upper"]
    assert ci_res["ci_level"] == 0.95


def test_paired_model_comparison_significant():
    y_true = np.array([0, 0, 0, 1, 1, 1, 1, 0, 1, 0] * 20)  # 200 samples
    # Model A is perfect
    scores_a = y_true.astype(float)
    # Model B is random
    rng = np.random.default_rng(42)
    scores_b = rng.uniform(0, 1, size=len(y_true))

    res = paired_model_comparison(
        y_true, scores_a, scores_b, model_a_name="ModelA", model_b_name="ModelB", n_bootstraps=200, seed=42
    )

    assert res["delta"] > 0
    assert res["is_statistically_significant"] is True
    assert res["superior_model"] == "ModelA"
    assert res["p_value"] < 0.05
    assert "outperforms with statistical significance" in res["scientific_statement"]


def test_paired_model_comparison_not_significant():
    y_true = np.array([0, 0, 1, 1] * 50)
    rng = np.random.default_rng(42)
    scores_a = rng.uniform(0, 1, size=len(y_true))
    # Scores B is nearly identical with tiny perturbation
    scores_b = np.clip(scores_a + rng.normal(0, 0.001, size=len(y_true)), 0, 1)

    res = paired_model_comparison(
        y_true, scores_a, scores_b, model_a_name="ModelA", model_b_name="ModelB", n_bootstraps=200, seed=42
    )

    assert res["is_statistically_significant"] is False
    assert "No statistically significant difference" in res["scientific_statement"]


def test_multi_seed_summary():
    runs = [
        {"f1": 0.90, "accuracy": 0.92, "roc_auc": 0.95},
        {"f1": 0.92, "accuracy": 0.94, "roc_auc": 0.96},
        {"f1": 0.88, "accuracy": 0.90, "roc_auc": 0.94},
    ]
    summary = multi_seed_summary(runs)

    assert "f1" in summary
    assert summary["f1"]["mean"] == 0.90
    assert summary["f1"]["runs"] == 3
    assert len(summary["f1"]["values"]) == 3
