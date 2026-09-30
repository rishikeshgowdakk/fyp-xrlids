"""Centralized evaluation metrics (build spec sections 26, 28-30, 39).

There is exactly ONE implementation of metrics in this project. Scripts must import
these functions rather than re-deriving metrics, so a number can never mean two
different things in two places.

Conventions
-----------
* Positive class is always ``1`` (ATTACK); negative class is ``0`` (BENIGN).
* ``y_true`` are integer labels; ``y_score`` are continuous scores/probabilities.
* ROC-AUC and PR-AUC are computed from *continuous scores only*. Passing thresholded
  0/1 predictions as scores is rejected, because that is the classic way to silently
  produce a meaningless AUC (build spec section 29).
* Undefined metrics (e.g. AUC with a single class present) return ``None`` plus a
  ``reason``; they are never replaced with a plausible-looking number.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

POSITIVE_CLASS = 1
NEGATIVE_CLASS = 0


class MetricError(ValueError):
    """Raised when inputs cannot support a scientifically valid metric."""


def _as_binary_int_array(values: Sequence[float] | np.ndarray, name: str) -> np.ndarray:
    arr = np.asarray(values)
    if arr.ndim != 1:
        raise MetricError(f"{name} must be 1-D, got shape {arr.shape}")
    if arr.size == 0:
        raise MetricError(f"{name} is empty; no population to evaluate")
    if not np.all(np.isin(arr, [0, 1])):
        bad = np.unique(arr[~np.isin(arr, [0, 1])])[:5]
        raise MetricError(f"{name} must contain only 0/1 labels; found {bad.tolist()}")
    return arr.astype(int)


def _as_score_array(values: Sequence[float] | np.ndarray, name: str) -> np.ndarray:
    arr = np.asarray(values, dtype=float)
    if arr.ndim != 1:
        raise MetricError(f"{name} must be 1-D, got shape {arr.shape}")
    if arr.size == 0:
        raise MetricError(f"{name} is empty; no population to evaluate")
    if not np.all(np.isfinite(arr)):
        raise MetricError(f"{name} contains non-finite values; refusing to score")
    return arr


def confusion_counts(y_true: Sequence[float], y_pred: Sequence[float]) -> dict[str, int]:
    """Return TN/FP/FN/TP with positive class = 1.

    Uses an explicit confusion matrix so the mapping to TN/FP/FN/TP is unambiguous
    rather than reconstructed from metadata.
    """
    yt = _as_binary_int_array(y_true, "y_true")
    yp = _as_binary_int_array(y_pred, "y_pred")
    if yt.shape != yp.shape:
        raise MetricError(f"y_true and y_pred length mismatch: {yt.shape} vs {yp.shape}")
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def binary_metrics(y_true: Sequence[float], y_pred: Sequence[float]) -> dict[str, Any]:
    """All threshold-dependent metrics for a fixed operating point.

    Formulas (see ``docs/phase1/METRICS.md``):
        Accuracy  = (TP+TN)/(TP+TN+FP+FN)
        Precision = TP/(TP+FP)
        Recall    = TP/(TP+FN)          (a.k.a. sensitivity / TPR)
        F1        = 2*P*R/(P+R)
        Specificity = TN/(TN+FP)        FPR = FP/(FP+TN) = 1-Specificity
        FNR       = FN/(FN+TP) = 1-Recall
    """
    counts = confusion_counts(y_true, y_pred)
    yt = _as_binary_int_array(y_true, "y_true")
    yp = _as_binary_int_array(y_pred, "y_pred")

    tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total
    precision = precision_score(yt, yp, pos_label=POSITIVE_CLASS, zero_division=0)
    recall = recall_score(yt, yp, pos_label=POSITIVE_CLASS, zero_division=0)
    specificity = tn / (tn + fp) if (tn + fp) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None

    return {
        "confusion": counts,
        "population": int(total),
        "positive_support": int(tp + fn),
        "negative_support": int(tn + fp),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1_score(yt, yp, pos_label=POSITIVE_CLASS, zero_division=0)),
        "macro_f1": float(f1_score(yt, yp, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(yt, yp, average="weighted", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(yt, yp)),
        "specificity": None if specificity is None else float(specificity),
        "fpr": None if fpr is None else float(fpr),
        "fnr": None if fnr is None else float(fnr),
        "per_class": {
            "benign": {
                "precision": float(precision_score(yt, yp, pos_label=0, zero_division=0)),
                "recall": float(recall_score(yt, yp, pos_label=0, zero_division=0)),
                "f1": float(f1_score(yt, yp, pos_label=0, zero_division=0)),
                "support": int(tn + fp),
            },
            "attack": {
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1_score(yt, yp, pos_label=1, zero_division=0)),
                "support": int(tp + fn),
            },
        },
    }


def score_metrics(y_true: Sequence[float], y_score: Sequence[float]) -> dict[str, Any]:
    """Threshold-independent metrics computed from continuous scores.

    Guards against the classic error of passing hard 0/1 predictions as ``y_score``:
    a two-point score distribution taking only {0,1} is rejected.
    """
    yt = _as_binary_int_array(y_true, "y_true")
    ys = _as_score_array(y_score, "y_score")
    if yt.shape != ys.shape:
        raise MetricError(f"y_true and y_score length mismatch: {yt.shape} vs {ys.shape}")

    unique = np.unique(ys)
    if unique.size <= 2 and np.all(np.isin(unique, [0.0, 1.0])):
        raise MetricError(
            "y_score looks like thresholded 0/1 predictions, not continuous scores. "
            "ROC-AUC/PR-AUC must be computed from scores (build spec section 29)."
        )

    if np.unique(yt).size < 2:
        return {
            "roc_auc": None,
            "pr_auc": None,
            "reason": "only one class present in y_true; AUC metrics are undefined",
        }

    return {
        "roc_auc": float(roc_auc_score(yt, ys)),
        "pr_auc": float(average_precision_score(yt, ys)),
        "reason": None,
    }


def evaluate(
    y_true: Sequence[float],
    y_score: Sequence[float],
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Full evaluation at one operating point on one population."""
    ys = _as_score_array(y_score, "y_score")
    yp = (ys >= threshold).astype(int)
    out: dict[str, Any] = {
        "threshold": float(threshold),
        "positive_class": POSITIVE_CLASS,
        "score_definition": "P(class=1) or a comparable continuous detector score",
    }
    out.update(binary_metrics(y_true, yp))
    out.update(score_metrics(y_true, ys))
    return out


def metric_audit() -> list[dict[str, str]]:
    """Machine-readable documentation of how each metric is implemented.

    Emitted into reports so a reader never has to guess which library call, population
    or averaging scheme produced a number.
    """
    return [
        {"metric": "accuracy", "formula": "(TP+TN)/(TP+TN+FP+FN)", "implementation": "explicit counts", "input": "hard labels", "edge_cases": "defined for all populations"},
        {"metric": "precision", "formula": "TP/(TP+FP)", "implementation": "sklearn.metrics.precision_score(pos_label=1, zero_division=0)", "input": "hard labels", "edge_cases": "0 when no positive predictions"},
        {"metric": "recall", "formula": "TP/(TP+FN)", "implementation": "sklearn.metrics.recall_score(pos_label=1, zero_division=0)", "input": "hard labels", "edge_cases": "0 when no positive support"},
        {"metric": "f1", "formula": "2PR/(P+R)", "implementation": "sklearn.metrics.f1_score(pos_label=1, zero_division=0)", "input": "hard labels", "edge_cases": "0 when P=R=0"},
        {"metric": "macro_f1", "formula": "mean of per-class F1", "implementation": "sklearn.metrics.f1_score(average='macro')", "input": "hard labels", "edge_cases": "unweighted; sensitive to minority class"},
        {"metric": "weighted_f1", "formula": "support-weighted mean of per-class F1", "implementation": "sklearn.metrics.f1_score(average='weighted')", "input": "hard labels", "edge_cases": "dominated by majority class"},
        {"metric": "balanced_accuracy", "formula": "(TPR+TNR)/2", "implementation": "sklearn.metrics.balanced_accuracy_score", "input": "hard labels", "edge_cases": "robust to imbalance"},
        {"metric": "specificity", "formula": "TN/(TN+FP)", "implementation": "explicit counts", "input": "hard labels", "edge_cases": "None when no negatives"},
        {"metric": "fpr", "formula": "FP/(FP+TN)", "implementation": "explicit counts", "input": "hard labels", "edge_cases": "None when no negatives"},
        {"metric": "fnr", "formula": "FN/(FN+TP)", "implementation": "explicit counts", "input": "hard labels", "edge_cases": "None when no positives"},
        {"metric": "roc_auc", "formula": "area under TPR-vs-FPR curve", "implementation": "sklearn.metrics.roc_auc_score", "input": "CONTINUOUS scores", "edge_cases": "None if one class present; rejects 0/1 scores"},
        {"metric": "pr_auc", "formula": "average precision", "implementation": "sklearn.metrics.average_precision_score", "input": "CONTINUOUS scores", "edge_cases": "None if one class present; prefer over ROC-AUC under imbalance"},
    ]
