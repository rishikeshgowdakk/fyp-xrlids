"""Statistical Robustness and Model Comparison Engine (Tasks 18, 19).

Provides quantitative statistical support for experimental claims:
- Empirical bootstrap confidence intervals (e.g. 95% CI for F1, ROC-AUC, Precision, Recall).
- Paired bootstrap hypothesis tests for model comparison (e.g. RF vs. Fusion, Decision Tree vs. RF).
- Multi-seed metric aggregation (mean, std, min, max, per-seed values).
- Enforces scientific rigor: prevents reports from using 'significantly better' without quantitative test support.
"""

from __future__ import annotations

from typing import Any, Callable

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score


def _calc_metric(y_true: np.ndarray, y_score: np.ndarray, metric_name: str, threshold: float = 0.5) -> float:
    """Evaluate a single scalar metric."""
    y_pred = (y_score >= threshold).astype(int)
    if metric_name == "f1":
        return float(f1_score(y_true, y_pred, zero_division=0))
    elif metric_name == "accuracy":
        return float(accuracy_score(y_true, y_pred))
    elif metric_name == "precision":
        return float(precision_score(y_true, y_pred, zero_division=0))
    elif metric_name == "recall":
        return float(recall_score(y_true, y_pred, zero_division=0))
    elif metric_name == "roc_auc":
        if len(np.unique(y_true)) < 2:
            return 0.5
        return float(roc_auc_score(y_true, y_score))
    else:
        raise ValueError(f"Unknown metric: {metric_name}")


def bootstrap_metric_ci(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    metric_name: str = "f1",
    threshold: float = 0.5,
    n_bootstraps: int = 1000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> dict[str, float]:
    """Compute empirical non-parametric bootstrap confidence interval for a metric."""
    yt = np.asarray(y_true, dtype=int)
    ys = np.asarray(y_score, dtype=float)
    n = len(yt)
    if n == 0:
        return {"point_estimate": 0.0, "ci_lower": 0.0, "ci_upper": 0.0, "std": 0.0}

    point_est = _calc_metric(yt, ys, metric_name, threshold)
    rng = np.random.default_rng(seed)

    boot_estimates = np.empty(n_bootstraps, dtype=float)
    for i in range(n_bootstraps):
        boot_idx = rng.integers(0, n, size=n)
        boot_estimates[i] = _calc_metric(yt[boot_idx], ys[boot_idx], metric_name, threshold)

    alpha = 1.0 - ci_level
    lower = float(np.percentile(boot_estimates, (alpha / 2.0) * 100))
    upper = float(np.percentile(boot_estimates, (1.0 - alpha / 2.0) * 100))

    return {
        "metric": metric_name,
        "point_estimate": round(point_est, 6),
        "ci_lower": round(lower, 6),
        "ci_upper": round(upper, 6),
        "ci_level": ci_level,
        "std": round(float(np.std(boot_estimates)), 6),
        "n_bootstraps": n_bootstraps,
    }


def paired_model_comparison(
    y_true: pd.Series | np.ndarray,
    scores_a: pd.Series | np.ndarray,
    scores_b: pd.Series | np.ndarray,
    *,
    model_a_name: str = "model_a",
    model_b_name: str = "model_b",
    metric_name: str = "f1",
    threshold: float = 0.5,
    n_bootstraps: int = 1000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> dict[str, Any]:
    """Perform paired bootstrap hypothesis test comparing model A vs model B.

    Tests null hypothesis H0: E[metric(A)] == E[metric(B)] on identical evaluation samples.
    """
    yt = np.asarray(y_true, dtype=int)
    sa = np.asarray(scores_a, dtype=float)
    sb = np.asarray(scores_b, dtype=float)

    if not (len(yt) == len(sa) == len(sb)):
        raise ValueError("y_true, scores_a, and scores_b must have identical lengths")

    n = len(yt)
    point_a = _calc_metric(yt, sa, metric_name, threshold)
    point_b = _calc_metric(yt, sb, metric_name, threshold)
    delta_point = point_a - point_b

    rng = np.random.default_rng(seed)
    deltas = np.empty(n_bootstraps, dtype=float)

    for i in range(n_bootstraps):
        boot_idx = rng.integers(0, n, size=n)
        b_yt = yt[boot_idx]
        val_a = _calc_metric(b_yt, sa[boot_idx], metric_name, threshold)
        val_b = _calc_metric(b_yt, sb[boot_idx], metric_name, threshold)
        deltas[i] = val_a - val_b

    alpha = 1.0 - ci_level
    ci_lower = float(np.percentile(deltas, (alpha / 2.0) * 100))
    ci_upper = float(np.percentile(deltas, (1.0 - alpha / 2.0) * 100))

    # Two-sided empirical p-value for difference
    # Fraction of bootstrap differences on the other side of 0
    p_le_zero = np.mean(deltas <= 0.0)
    p_ge_zero = np.mean(deltas >= 0.0)
    p_value = float(min(1.0, 2.0 * min(p_le_zero, p_ge_zero)))

    # Is statistically significant at alpha? (CI excludes 0)
    is_significant = bool((ci_lower > 0.0 and ci_upper > 0.0) or (ci_lower < 0.0 and ci_upper < 0.0))

    better_model = "equal"
    if is_significant:
        better_model = model_a_name if delta_point > 0 else model_b_name

    return {
        "model_a": model_a_name,
        "model_b": model_b_name,
        "metric": metric_name,
        "estimate_a": round(point_a, 6),
        "estimate_b": round(point_b, 6),
        "delta": round(delta_point, 6),
        "ci_lower": round(ci_lower, 6),
        "ci_upper": round(ci_upper, 6),
        "ci_level": ci_level,
        "p_value": round(p_value, 6),
        "is_statistically_significant": is_significant,
        "superior_model": better_model,
        "scientific_statement": (
            f"{better_model.upper()} outperforms with statistical significance "
            f"(Δ={delta_point:+.4f}, {int(ci_level*100)}% CI [{ci_lower:.4f}, {ci_upper:.4f}], p={p_value:.4f})"
            if is_significant
            else f"No statistically significant difference observed between {model_a_name} and {model_b_name} "
                 f"(Δ={delta_point:+.4f}, {int(ci_level*100)}% CI [{ci_lower:.4f}, {ci_upper:.4f}], p={p_value:.4f})"
        ),
    }


def multi_seed_summary(per_seed_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate metric dictionaries across multiple repeated seeds."""
    if not per_seed_metrics:
        return {}

    all_keys = [k for k in per_seed_metrics[0].keys() if isinstance(per_seed_metrics[0][k], (int, float))]
    summary: dict[str, Any] = {}

    for k in all_keys:
        vals = [float(m[k]) for m in per_seed_metrics if k in m and m[k] is not None]
        if vals:
            summary[k] = {
                "mean": round(float(np.mean(vals)), 6),
                "std": round(float(np.std(vals)), 6),
                "min": round(float(np.min(vals)), 6),
                "max": round(float(np.max(vals)), 6),
                "runs": len(vals),
                "values": [round(v, 6) for v in vals],
            }

    return summary
