"""Baseline Ladder Detectors (Task 8: Minimum Useful Comparison Set).

Implements deterministic reference baselines to evaluate whether the complexity
of RF, LSTM, and Fusion provides measurable value over simpler paradigms:
1. MajorityClassDetector (empirical class prior baseline)
2. LogisticRegressionDetector (convex linear baseline)
3. DecisionTreeDetector (single interpretable tree baseline)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier


@dataclass
class MajorityClassDetector:
    """Predicts the most frequent training class and empirical prior."""

    majority_class: int = 0
    prior_probability: float = 0.0
    feature_names: list[str] = field(default_factory=list)
    fitted: bool = False

    def fit(self, X: pd.DataFrame | np.ndarray, y: pd.Series | np.ndarray) -> MajorityClassDetector:
        y_arr = np.asarray(y, dtype=int)
        counts = np.bincount(y_arr, minlength=2)
        self.majority_class = int(np.argmax(counts))
        self.prior_probability = float(counts[1] / max(1, len(y_arr)))
        if isinstance(X, pd.DataFrame):
            self.feature_names = list(X.columns)
        self.fitted = True
        return self

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        n = len(X)
        return np.full(n, self.prior_probability, dtype=np.float32)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        n = len(X)
        return np.full(n, self.majority_class, dtype=int)

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "majority_class",
            "majority_class": self.majority_class,
            "prior_probability": self.prior_probability,
            "feature_count": len(self.feature_names),
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_dir():
            target = target / "majority_class.joblib"
        joblib.dump(self, target)
        return target

    @classmethod
    def load(cls, path: str | Path) -> MajorityClassDetector:
        return joblib.load(path)


class LogisticRegressionDetector:
    """Standardized deterministic linear classification baseline."""

    def __init__(
        self,
        params: dict[str, Any] | None = None,
        feature_names: Sequence[str] | None = None,
        seed: int = 42,
    ) -> None:
        self.params = {
            "max_iter": 1000,
            "random_state": seed,
            "solver": "lbfgs",
            "class_weight": "balanced",
            **(params or {}),
        }
        self.feature_names = list(feature_names or [])
        self.model = LogisticRegression(**self.params)
        self.fitted = False

    def fit(
        self, X: pd.DataFrame | np.ndarray, y: pd.Series | np.ndarray
    ) -> LogisticRegressionDetector:
        if isinstance(X, pd.DataFrame) and not self.feature_names:
            self.feature_names = list(X.columns)
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        y_arr = y.to_numpy(dtype=int) if isinstance(y, pd.Series) else np.asarray(y, dtype=int)
        self.model.fit(X_mat, y_arr)
        self.fitted = True
        return self

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        probs = self.model.predict_proba(X_mat)
        if probs.shape[1] == 2:
            return probs[:, 1].astype(np.float32)
        return probs[:, 0].astype(np.float32)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "logistic_regression",
            "parameters": self.params,
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_dir():
            target = target / "logistic_regression.joblib"
        joblib.dump(self, target)
        return target

    @classmethod
    def load(cls, path: str | Path) -> LogisticRegressionDetector:
        return joblib.load(path)


class DecisionTreeDetector:
    """Standardized deterministic single-tree baseline."""

    def __init__(
        self,
        params: dict[str, Any] | None = None,
        feature_names: Sequence[str] | None = None,
        seed: int = 42,
    ) -> None:
        self.params = {
            "max_depth": 10,
            "min_samples_leaf": 5,
            "random_state": seed,
            "class_weight": "balanced",
            **(params or {}),
        }
        self.feature_names = list(feature_names or [])
        self.model = DecisionTreeClassifier(**self.params)
        self.fitted = False

    def fit(
        self, X: pd.DataFrame | np.ndarray, y: pd.Series | np.ndarray
    ) -> DecisionTreeDetector:
        if isinstance(X, pd.DataFrame) and not self.feature_names:
            self.feature_names = list(X.columns)
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        y_arr = y.to_numpy(dtype=int) if isinstance(y, pd.Series) else np.asarray(y, dtype=int)
        self.model.fit(X_mat, y_arr)
        self.fitted = True
        return self

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        probs = self.model.predict_proba(X_mat)
        if probs.shape[1] == 2:
            return probs[:, 1].astype(np.float32)
        return probs[:, 0].astype(np.float32)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "decision_tree",
            "parameters": self.params,
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_dir():
            target = target / "decision_tree.joblib"
        joblib.dump(self, target)
        return target

    @classmethod
    def load(cls, path: str | Path) -> DecisionTreeDetector:
        return joblib.load(path)
