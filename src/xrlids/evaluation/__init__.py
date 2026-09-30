"""Evaluation: centralized metrics, calibration, thresholding, error analysis."""

from xrlids.evaluation.metrics import (
    MetricError,
    binary_metrics,
    confusion_counts,
    evaluate,
    metric_audit,
    score_metrics,
)

__all__ = [
    "MetricError",
    "binary_metrics",
    "confusion_counts",
    "evaluate",
    "metric_audit",
    "score_metrics",
]
