"""XGBoost detector for XRL-IDARS (Phase 2 Candidate).

Hyperparameters are configuration-driven, never hardcoded.
Exposes a continuous score P(class=1) for threat probability assessment.
Provides model persistence via native XGBoost JSON serialization alongside metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd
import xgboost as xgb

from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _mark_classifier_estimator(model: xgb.XGBClassifier) -> xgb.XGBClassifier:
    """Keep sklearn classifier metadata explicit across sklearn tag API changes."""
    model._estimator_type = "classifier"
    return model

DEFAULT_XGB_PARAMS: dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.10,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 42,
    "eval_metric": "logloss",
    "tree_method": "hist",
    "n_jobs": min(4, os.cpu_count() or 1),
}


class XGBoostError(RuntimeError):
    """Raised when the XGBoost detector cannot be trained, scored, or loaded."""


@dataclass
class XGBoostDetector:
    """Config-driven detector wrapper around xgboost.XGBClassifier."""

    params: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_XGB_PARAMS))
    feature_names: list[str] = field(default_factory=list)
    model: xgb.XGBClassifier | None = field(default=None, repr=False)
    n_train_rows: int = 0

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_XGB_PARAMS)
        merged.update(self.params or {})
        configured_jobs = merged.get("n_jobs", -1)
        if configured_jobs in (-1, 0):
            clamped = min(4, os.cpu_count() or 1)
            logger.info("XGBoost n_jobs=%d clamped to %d for resource safety", configured_jobs, clamped)
            merged["n_jobs"] = clamped
        self.params = merged

    def fit(
        self,
        X: pd.DataFrame | np.ndarray,
        y: pd.Series | np.ndarray,
        eval_set: list[tuple[Any, Any]] | None = None,
        early_stopping_rounds: int | None = None,
        feature_names: Sequence[str] | None = None,
    ) -> "XGBoostDetector":
        """Fit the XGBClassifier on training data with optional early stopping."""
        if self.model is not None:
            raise XGBoostError("detector is already fitted; create a new instance")

        if isinstance(X, pd.DataFrame):
            self.feature_names = list(X.columns)
            X_arr = X.to_numpy(dtype=float)
        else:
            X_arr = np.asarray(X, dtype=float)
            if feature_names is not None:
                self.feature_names = list(feature_names)
            elif not self.feature_names:
                self.feature_names = [f"f{i}" for i in range(X_arr.shape[1])]

        y_arr = np.asarray(y, dtype=int).ravel()

        if len(X_arr) != len(y_arr):
            raise XGBoostError(f"X ({len(X_arr)}) and y ({len(y_arr)}) have different lengths")

        if len(np.unique(y_arr)) < 2:
            raise XGBoostError("training labels contain a single class; cannot fit a detector")

        fit_params: dict[str, Any] = dict(self.params)
        if early_stopping_rounds is not None and early_stopping_rounds > 0:
            fit_params["early_stopping_rounds"] = early_stopping_rounds

        self.model = _mark_classifier_estimator(xgb.XGBClassifier(**fit_params))

        formatted_eval_set = None
        if eval_set:
            formatted_eval_set = []
            for ex, ey in eval_set:
                ex_arr = ex.to_numpy(dtype=float) if isinstance(ex, pd.DataFrame) else np.asarray(ex, dtype=float)
                ey_arr = np.asarray(ey, dtype=int).ravel()
                formatted_eval_set.append((ex_arr, ey_arr))

        logger.info("Fitting XGBoost with n_jobs=%d, n_estimators=%d", fit_params.get("n_jobs", 1), fit_params.get("n_estimators", 100))
        self.model.fit(X_arr, y_arr, eval_set=formatted_eval_set, verbose=False)
        self.n_train_rows = int(len(X_arr))
        logger.info("XGBoost fitted rows=%d features=%d", self.n_train_rows, len(self.feature_names))
        return self

    def _check(self) -> xgb.XGBClassifier:
        if self.model is None:
            raise XGBoostError("detector is not fitted")
        return self.model

    def _prepare_input(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        if isinstance(X, pd.DataFrame):
            if self.feature_names and list(X.columns) != self.feature_names:
                raise XGBoostError(
                    "feature order/name mismatch between training and inference:\n"
                    f"expected={self.feature_names}\ngot={list(X.columns)}"
                )
            return X.to_numpy(dtype=float)
        arr = np.asarray(X, dtype=float)
        if self.feature_names and arr.ndim > 1 and arr.shape[1] != len(self.feature_names):
            raise XGBoostError(
                f"Feature dimension mismatch: expected {len(self.feature_names)}, got {arr.shape[1]}"
            )
        return arr

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Continuous score = P(class = 1). Never returns hard labels."""
        model = self._check()
        X_arr = self._prepare_input(X)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)
        proba = model.predict_proba(X_arr)
        return proba[:, 1]

    def predict(self, X: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Hard labels at an explicit threshold."""
        return (self.predict_proba(X) >= threshold).astype(int)

    def feature_importances(self) -> pd.DataFrame:
        """Return feature importances as a sorted DataFrame."""
        model = self._check()
        importances = model.feature_importances_
        names = self.feature_names if self.feature_names else [f"f{i}" for i in range(len(importances))]
        return (
            pd.DataFrame({"feature": names, "importance": importances})
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "XGBoost",
            "params": dict(self.params),
            "n_features": len(self.feature_names),
            "feature_names": list(self.feature_names),
            "n_train_rows": self.n_train_rows,
        }

    def save(self, destination: str | Path) -> Path:
        """Save model and metadata to destination.
        
        If destination is a directory, saves to destination / 'xgboost_cicids2017.json'
        and destination / 'xgboost_metadata.json'.
        If destination is a file path ending in .json, saves model to that path
        and metadata to path.with_suffix('.meta.json').
        """
        dest = Path(destination)
        if dest.is_dir() or not dest.suffix:
            dest.mkdir(parents=True, exist_ok=True)
            model_file = dest / "xgboost_cicids2017.json"
            meta_file = dest / "xgboost_metadata.json"
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            model_file = dest
            meta_file = dest.with_name(f"{dest.stem}_meta.json")

        model = self._check()
        model.save_model(str(model_file))

        metadata = {
            "params": self.params,
            "feature_names": self.feature_names,
            "n_train_rows": self.n_train_rows,
            "model_file": model_file.name,
        }
        meta_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        logger.info("Saved XGBoost model to %s and metadata to %s", model_file, meta_file)
        return model_file

    @classmethod
    def load(cls, source: str | Path) -> "XGBoostDetector":
        """Load XGBoost model and metadata from source file or directory."""
        src = Path(source)
        if src.is_dir():
            model_file = src / "xgboost_cicids2017.json"
            meta_file = src / "xgboost_metadata.json"
            if not model_file.exists():
                json_files = list(src.glob("*.json"))
                candidates = [f for f in json_files if not f.name.endswith("_meta.json") and not f.name.endswith(".meta.json")]
                if candidates:
                    model_file = candidates[0]
                    meta_file = src / f"{model_file.stem}_meta.json"
        elif src.suffix == ".json":
            model_file = src
            meta_file = src.with_name(f"{src.stem}_meta.json")
            if not meta_file.exists():
                meta_file = src.with_name(f"{src.stem}.meta.json")
        else:
            raise XGBoostError(f"Unsupported XGBoost source path: {src}")

        if not model_file.exists():
            raise XGBoostError(f"XGBoost model file not found: {model_file}")

        params: dict[str, Any] = dict(DEFAULT_XGB_PARAMS)
        feature_names: list[str] = []
        n_train_rows: int = 0

        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                params = meta.get("params", params)
                feature_names = meta.get("feature_names", feature_names)
                n_train_rows = meta.get("n_train_rows", 0)
            except Exception as e:
                logger.warning("Could not read XGBoost metadata from %s: %s", meta_file, e)

        model = _mark_classifier_estimator(xgb.XGBClassifier(**params))
        model.load_model(str(model_file))

        detector = cls(
            params=params,
            feature_names=feature_names,
            model=model,
            n_train_rows=n_train_rows,
        )
        return detector
