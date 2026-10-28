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
from sklearn.ensemble import IsolationForest
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


class IsolationForestDetector:
    """Unsupervised anomaly detection baseline fit exclusively on benign traffic (y == 0).

    CRITICAL SCIENTIFIC & MATHEMATICAL SEMANTICS:
    1. Training Paradigm:
       Fits exclusively on training data where ground truth label y == 0 (benign baseline).
       Supervised attack labels (y == 1) are NEVER exposed during training.
    2. Score Orientation & Raw Metrics:
       - score_samples(X): scikit-learn's opposite of anomaly score (higher = more normal / inlier).
       - decision_function(X): score_samples(X) - offset_. Inliers yield positive values,
         outliers yield negative values.
    3. Uncalibrated Monotonic Anomaly Score:
       - anomaly_score(X): maps decision_function(X) to [0.0, 1.0] via logistic sigmoid:
           anomaly_score(x) = 1.0 / (1.0 + exp(sigmoid_scale * decision_function(x)))
         Under this mapping, decision_function < 0 (outliers) maps to anomaly_score > 0.5,
         and decision_function > 0 (inliers) maps to anomaly_score < 0.5.
       - IMPORTANT: anomaly_score is an UNCALIBRATED monotonic outlierness metric, NOT a
         calibrated Bayesian posterior probability P(attack | x). True posterior calibration
         requires supervised calibration sets (e.g. Platt scaling / Isotonic regression)
         which violates the unsupervised zero-attack-exposure premise.
    4. Estimator Compatibility:
       - predict_proba(X): returns anomaly_score(X) for API compatibility with binary
         estimators.
    5. Rank Invariance:
       - Since the logistic sigmoid is strictly monotonic decreasing in decision_function,
         the rank ordering of anomaly_score is identical to -decision_function.
         Therefore, continuous rank metrics like ROC-AUC are mathematically invariant
         to the sigmoid transformation.
    """

    def __init__(
        self,
        params: dict[str, Any] | None = None,
        feature_names: Sequence[str] | None = None,
        seed: int = 42,
    ) -> None:
        self.params = {
            "n_estimators": 100,
            "max_samples": "auto",
            "contamination": "auto",
            "random_state": seed,
            "n_jobs": -1,
            **(params or {}),
        }
        self.feature_names = list(feature_names or [])
        self.model = IsolationForest(**self.params)
        self.fitted = False
        self.sigmoid_scale: float = 10.0

    def fit(
        self,
        X: pd.DataFrame | np.ndarray,
        y: pd.Series | np.ndarray | None = None,
    ) -> IsolationForestDetector:
        """Fit isolation forest on benign instances only (y == 0 if y is provided)."""
        if isinstance(X, pd.DataFrame) and not self.feature_names:
            self.feature_names = list(X.columns)

        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)

        if y is not None:
            y_arr = y.to_numpy(dtype=int) if isinstance(y, pd.Series) else np.asarray(y, dtype=int)
            benign_mask = (y_arr == 0)
            X_train = X_mat[benign_mask]
        else:
            X_train = X_mat

        self.model.fit(X_train)
        self.fitted = True
        return self

    def decision_function(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Return raw scikit-learn decision function (positive = inlier, negative = outlier)."""
        if not self.fitted:
            raise RuntimeError("IsolationForestDetector must be fitted before decision_function().")
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        return self.model.decision_function(X_mat)

    def score_samples(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Return raw scikit-learn score samples (higher = more normal / inlier)."""
        if not self.fitted:
            raise RuntimeError("IsolationForestDetector must be fitted before score_samples().")
        X_mat = X.to_numpy(dtype=np.float32) if isinstance(X, pd.DataFrame) else np.asarray(X, dtype=np.float32)
        return self.model.score_samples(X_mat)

    def anomaly_score(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Return uncalibrated continuous anomaly score in [0.0, 1.0] where higher = more anomalous.

        IsolationForest.decision_function(X) outputs positive values for inliers (normal)
        and negative values for outliers (anomalous). We invert the sign and pass through
        a logistic sigmoid: P(anomaly) = 1 / (1 + exp(scale * decision_function(X))).

        NOTE: This is a monotonic ranking metric of outlierness, NOT a calibrated Bayesian
        posterior probability P(attack | x).
        """
        df = self.decision_function(X)
        scores = 1.0 / (1.0 + np.exp(self.sigmoid_scale * df))
        return scores.astype(np.float32)

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Estimator compatibility alias for anomaly_score(X).

        Returns continuous uncalibrated anomaly scores in [0.0, 1.0] where higher = more anomalous.
        Satisfies scikit-learn probability interface expectations for binary evaluation.
        """
        return self.anomaly_score(X)

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.anomaly_score(X) >= threshold).astype(int)

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "isolation_forest",
            "parameters": self.params,
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
            "sigmoid_scale": self.sigmoid_scale,
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_dir():
            target = target / "isolation_forest.joblib"
        joblib.dump(self, target)
        return target

    @classmethod
    def load(cls, path: str | Path) -> IsolationForestDetector:
        return joblib.load(path)

