"""Calibration analysis (build spec section 39; Checkpoint 6).

A detector score is NOT "confidence" until calibration supports that reading. These
utilities measure whether a score of 0.9 corresponds to roughly 90% empirical event
frequency, and optionally fit a calibrator on VALIDATION data only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd


class CalibrationError(ValueError):
    """Raised when calibration inputs are invalid."""


def reliability_curve(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    n_bins: int = 10,
) -> pd.DataFrame:
    """Bin predictions and compare mean predicted probability to observed frequency."""
    yt = np.asarray(y_true, dtype=int)
    ys = np.asarray(y_score, dtype=float)
    if yt.shape != ys.shape:
        raise CalibrationError("y_true and y_score must have the same shape")
    if n_bins < 2:
        raise CalibrationError("n_bins must be >= 2")

    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(ys, edges[1:-1], right=False), 0, n_bins - 1)

    rows = []
    for b in range(n_bins):
        mask = idx == b
        count = int(mask.sum())
        rows.append(
            {
                "bin": b,
                "lower": float(edges[b]),
                "upper": float(edges[b + 1]),
                "count": count,
                "mean_predicted": float(ys[mask].mean()) if count else None,
                "observed_frequency": float(yt[mask].mean()) if count else None,
                "gap": (float(ys[mask].mean()) - float(yt[mask].mean())) if count else None,
            }
        )
    return pd.DataFrame(rows)


def brier_score(y_true: pd.Series | np.ndarray, y_score: pd.Series | np.ndarray) -> float:
    """Mean squared error between probability and outcome."""
    yt = np.asarray(y_true, dtype=float)
    ys = np.asarray(y_score, dtype=float)
    if yt.shape != ys.shape:
        raise CalibrationError("y_true and y_score must have the same shape")
    return float(np.mean((ys - yt) ** 2))


def expected_calibration_error(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    n_bins: int = 10,
) -> float:
    """Count-weighted mean absolute gap between predicted and observed frequency."""
    curve = reliability_curve(y_true, y_score, n_bins=n_bins)
    total = curve["count"].sum()
    if total == 0:
        raise CalibrationError("no samples to calibrate on")
    gaps = curve["gap"].abs().fillna(0.0) * curve["count"]
    return float(gaps.sum() / total)


@dataclass
class CalibrationReport:
    brier: float
    ece: float
    n_bins: int
    curve: pd.DataFrame
    population_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "brier_score": self.brier,
            "expected_calibration_error": self.ece,
            "n_bins": self.n_bins,
            "population_size": self.population_size,
            "reliability_curve": self.curve.to_dict(orient="records"),
            "interpretation": (
                "score treated as probability: a well-calibrated model has ECE near 0. "
                "If ECE is large, do not call the raw score 'confidence'."
            ),
        }


def calibration_report(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    n_bins: int = 10,
) -> CalibrationReport:
    ys = np.asarray(y_score, dtype=float)
    return CalibrationReport(
        brier=brier_score(y_true, ys),
        ece=expected_calibration_error(y_true, ys, n_bins=n_bins),
        n_bins=n_bins,
        curve=reliability_curve(y_true, ys, n_bins=n_bins),
        population_size=int(len(ys)),
    )


@dataclass
class PlattCalibrator:
    """Logistic (Platt) calibration fitted on VALIDATION scores only.

    Never fit this on the test set: that would make the reported calibration optimistic.
    """

    a: float | None = None
    b: float | None = None
    fitted_on: str = "validation"

    def fit(self, y_true: pd.Series | np.ndarray, y_score: pd.Series | np.ndarray) -> "PlattCalibrator":
        from sklearn.linear_model import LogisticRegression

        yt = np.asarray(y_true, dtype=int)
        ys = np.asarray(y_score, dtype=float).reshape(-1, 1)
        if len(np.unique(yt)) < 2:
            raise CalibrationError("cannot fit Platt scaling with a single class present")
        lr = LogisticRegression()
        lr.fit(ys, yt)
        self.a = float(lr.coef_[0][0])
        self.b = float(lr.intercept_[0])
        return self

    def transform(self, y_score: pd.Series | np.ndarray) -> np.ndarray:
        if self.a is None or self.b is None:
            raise CalibrationError("calibrator is not fitted")
        ys = np.asarray(y_score, dtype=float)
        return 1.0 / (1.0 + np.exp(-(self.a * ys + self.b)))

    def to_dict(self) -> dict[str, Any]:
        return {"method": "platt_scaling", "a": self.a, "b": self.b, "fitted_on": self.fitted_on}
