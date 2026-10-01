"""Random Forest detector (build spec section 14).

Hyperparameters come from configuration, never from hardcoded constants in training code.
The detector exposes a continuous score (probability of class 1) which is what the
calibration, thresholding, fusion and AUC stages require.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

import os

DEFAULT_RF_PARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "max_depth": 16,
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": 42,
    "n_jobs": min(4, os.cpu_count() or 1),
}


class RandomForestError(RuntimeError):
    """Raised when the RF cannot be trained or scored."""


@dataclass
class RandomForestDetector:
    """Thin, config-driven wrapper around scikit-learn's RandomForestClassifier."""

    params: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_RF_PARAMS))
    feature_names: list[str] = field(default_factory=list)
    model: RandomForestClassifier | None = field(default=None, repr=False)
    n_train_rows: int = 0

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_RF_PARAMS)
        merged.update(self.params or {})
        # If user explicitly configured -1 or 0, cap at reasonable parallelism (e.g. min(4, os.cpu_count()))
        # to avoid OOM from excessive worker process forking on memory-constrained systems
        configured_jobs = merged.get("n_jobs", -1)
        if configured_jobs in (-1, 0):
            clamped = min(4, os.cpu_count() or 1)
            logger.info("RandomForest n_jobs=%d clamped to %d for resource safety", configured_jobs, clamped)
            merged["n_jobs"] = clamped
        self.params = merged

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "RandomForestDetector":
        if self.model is not None:
            raise RandomForestError("detector is already fitted; create a new instance")
        if len(X) != len(y):
            raise RandomForestError("X and y have different lengths")
        if y.nunique() < 2:
            raise RandomForestError("training labels contain a single class; cannot fit a detector")
        self.feature_names = list(X.columns)
        n_workers = self.params.get("n_jobs", 1)
        logger.info("Fitting RandomForest with n_jobs=%d workers", n_workers)
        self.model = RandomForestClassifier(**self.params)
        self.model.fit(X.to_numpy(dtype=float), y.to_numpy(dtype=int))
        self.n_train_rows = int(len(X))
        logger.info("RF fitted rows=%d features=%d n_jobs=%d", self.n_train_rows, len(self.feature_names), n_workers)
        return self

    def _check(self) -> RandomForestClassifier:
        if self.model is None:
            raise RandomForestError("detector is not fitted")
        return self.model

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Continuous score = P(class = 1). Never returns hard labels."""
        model = self._check()
        if list(X.columns) != self.feature_names:
            raise RandomForestError(
                "feature order/name mismatch between training and inference:\n"
                f"expected={self.feature_names}\ngot={list(X.columns)}"
            )
        return model.predict_proba(X.to_numpy(dtype=float))[:, 1]

    def predict(self, X: pd.DataFrame, threshold: float = 0.5) -> np.ndarray:
        """Hard labels at an explicit threshold (default 0.5, not a research choice)."""
        return (self.predict_proba(X) >= threshold).astype(int)

    def feature_importances(self) -> pd.DataFrame:
        model = self._check()
        return (
            pd.DataFrame(
                {"feature": self.feature_names, "importance": model.feature_importances_}
            )
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )

    def config(self) -> dict[str, Any]:
        return {"model_type": "RandomForest", "params": dict(self.params), "n_features": len(self.feature_names)}

    def save(self, directory: str | Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "random_forest.joblib"
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(directory: str | Path) -> "RandomForestDetector":
        return joblib.load(Path(directory) / "random_forest.joblib")
