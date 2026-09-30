"""Evaluation: centralized metrics, calibration, thresholding."""

from xrlids.evaluation.calibration import (
    CalibrationError,
    CalibrationReport,
    PlattCalibrator,
    brier_score,
    calibration_report,
    expected_calibration_error,
    reliability_curve,
)
from xrlids.evaluation.metrics import (
    MetricError,
    binary_metrics,
    confusion_counts,
    evaluate,
    metric_audit,
    score_metrics,
)
from xrlids.evaluation.thresholding import (
    DECISION_ID,
    DECISION_STATUS,
    OBJECTIVES,
    ThresholdError,
    candidate_operating_points,
    threshold_sweep,
)

__all__ = [
    "MetricError",
    "binary_metrics",
    "confusion_counts",
    "evaluate",
    "metric_audit",
    "score_metrics",
    "CalibrationError",
    "CalibrationReport",
    "PlattCalibrator",
    "brier_score",
    "calibration_report",
    "expected_calibration_error",
    "reliability_curve",
    "ThresholdError",
    "threshold_sweep",
    "candidate_operating_points",
    "DECISION_ID",
    "DECISION_STATUS",
    "OBJECTIVES",
]
