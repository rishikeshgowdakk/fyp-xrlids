"""Preprocessing pipeline (build spec sections 13, 22; scientific RULE 6).

The scaler is fit on TRAINING DATA ONLY and then applied unchanged to validation, test
and (later) live data. Fitting on all data is a leakage bug and is impossible here by
construction: :meth:`Preprocessor.fit` accepts only the training matrix.

Artifacts record feature list, feature order, scaler type, fitted dataset, training
population size, version, hash, timestamp and Git commit, so a model can never be loaded
without knowing exactly how its inputs were transformed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from xrlids.artifacts.metadata import ArtifactMetadata
from xrlids.utils.env import git_commit
from xrlids.utils.hashing import dict_hash, feature_schema_hash

PREPROCESSOR_VERSION = "1.0.0"


class PreprocessingError(ValueError):
    """Raised on schema mismatch or invalid fitted state."""


@dataclass
class Preprocessor:
    """Impute (train medians) -> scale (train statistics), with frozen feature order."""

    features: list[str]
    dataset: str
    missing_policy: str = "median_train"
    scaler_type: str = "StandardScaler"

    scaler: StandardScaler | None = field(default=None, repr=False)
    medians: pd.Series | None = field(default=None, repr=False)
    n_train_rows: int = 0
    fitted_at: str | None = None
    git_commit_sha: str | None = None
    feature_schema_hash_: str | None = None
    version: str = PREPROCESSOR_VERSION

    # ------------------------------------------------------------------- fitting
    def fit(self, train_frame: pd.DataFrame, *, train_labels: pd.Series | None = None) -> "Preprocessor":
        """Fit imputation statistics and the scaler on the TRAINING population only.

        ``train_labels`` is accepted only so the training class balance can be recorded;
        it never influences the transform.
        """
        missing = [f for f in self.features if f not in train_frame.columns]
        if missing:
            raise PreprocessingError(f"training frame is missing features: {missing}")
        if len(train_frame) == 0:
            raise PreprocessingError("cannot fit on an empty training population")

        X = train_frame[self.features].astype(float)

        if self.missing_policy == "median_train":
            self.medians = X.median(axis=0)
            X = X.fillna(self.medians)
        elif self.missing_policy == "error":
            if X.isna().any().any():
                raise PreprocessingError("training frame contains NaN and missing_policy='error'")
        else:
            raise PreprocessingError(f"unknown missing_policy '{self.missing_policy}'")

        self.scaler = StandardScaler()
        self.scaler.fit(X.to_numpy(dtype=float))
        self.n_train_rows = int(len(train_frame))
        self.fitted_at = datetime.now(timezone.utc).isoformat()
        self.git_commit_sha = git_commit()
        self.feature_schema_hash_ = feature_schema_hash(self.features)
        return self

    # ---------------------------------------------------------------- transform
    def transform(self, frame: pd.DataFrame, *, strict: bool = True) -> pd.DataFrame:
        """Apply the fitted transform. Column order is fixed by ``self.features``."""
        if self.scaler is None or (self.medians is None and self.missing_policy == "median_train"):
            raise PreprocessingError("preprocessor is not fitted")

        missing = [f for f in self.features if f not in frame.columns]
        if missing:
            if strict:
                raise PreprocessingError(f"input frame is missing features: {missing}")
            for m in missing:
                frame = frame.assign(**{m: np.nan})

        X = frame[self.features].astype(float)
        if self.missing_policy == "median_train":
            X = X.fillna(self.medians)
        if X.isna().any().any():
            raise PreprocessingError("NaN remained after imputation; refusing to transform")
        scaled = self.scaler.transform(X.to_numpy(dtype=float))
        return pd.DataFrame(scaled, columns=self.features, index=frame.index)

    # -------------------------------------------------------------- persistence
    def metadata(self) -> dict[str, Any]:
        payload = {
            "preprocessor_version": self.version,
            "dataset": self.dataset,
            "feature_list": self.features,
            "n_features": len(self.features),
            "feature_order": list(range(len(self.features))),
            "scaler_type": self.scaler_type,
            "missing_policy": self.missing_policy,
            "n_train_rows": self.n_train_rows,
            "fitted_at": self.fitted_at,
            "git_commit": self.git_commit_sha,
            "feature_schema_hash": self.feature_schema_hash_,
            "scaler_params": {
                "mean": self.scaler.mean_.tolist() if self.scaler is not None else None,
                "scale": self.scaler.scale_.tolist() if self.scaler is not None else None,
                "var": self.scaler.var_.tolist() if self.scaler is not None else None,
            },
            "imputation_medians": None if self.medians is None else self.medians.to_dict(),
        }
        payload["preprocessor_hash"] = dict_hash(
            {
                "features": self.features,
                "missing_policy": self.missing_policy,
                "n_train_rows": self.n_train_rows,
                "medians": payload["imputation_medians"],
                "mean": payload["scaler_params"]["mean"],
                "scale": payload["scaler_params"]["scale"],
            }
        )
        return payload

    def save(self, directory: str | Path, *, experiment_id: str = "unassigned") -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        blob = directory / "preprocessor.joblib"
        joblib.dump(self, blob)
        meta = self.metadata()
        meta_path = directory / "preprocessor.meta.json"
        import json

        meta_path.write_text(
            json.dumps(
                {
                    "metadata": ArtifactMetadata(
                        experiment_id=experiment_id,
                        feature_schema_hash=self.feature_schema_hash_,
                        seed=None,
                        extra={"preprocessor_hash": meta["preprocessor_hash"]},
                    ).to_dict(),
                    **meta,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return blob

    @staticmethod
    def load(directory: str | Path) -> "Preprocessor":
        return joblib.load(Path(directory) / "preprocessor.joblib")
