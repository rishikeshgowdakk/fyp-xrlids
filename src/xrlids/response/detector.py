"""Frozen Phase 1 detector interface for Phase 2 response layer (Task 1).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 3:
    Continuous Output Contract:
    Detector emits a continuous attack risk score S_t in [0.0, 1.0] (such as RF tree-vote
    fraction or calibrated probability when explicitly configured).

Strict Invariants:
1. Model weights and preprocessors are loaded read-only; no gradient backpropagation,
   retraining, or parameter adaptation is permitted.
2. The detector output is treated as a continuous risk score S_t, not an assumed
   calibrated posterior probability unless a calibration artifact is explicitly loaded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd

from xrlids.evaluation.calibration import PlattCalibrator
from xrlids.models.random_forest import RandomForestDetector
from xrlids.preprocessing.pipeline import Preprocessor


@dataclass
class FrozenDetector:
    """Read-only wrapper providing continuous attack risk scores from Phase 1 models."""

    preprocessor: Preprocessor
    model: Any  # Trained Phase 1 model (e.g. RandomForestDetector)
    calibrator: PlattCalibrator | None = None
    experiment_id: str = "EXP-P1-CIC2017-R10-001"
    score_type: str = "tree_vote_fraction"

    @classmethod
    def load(
        cls,
        experiment_dir: str | Path,
        *,
        model_filename: str = "random_forest.joblib",
        use_calibration: bool = False,
    ) -> "FrozenDetector":
        """Load frozen preprocessor and trained detector weights from Phase 1 experiment directory."""
        exp_path = Path(experiment_dir)
        if not exp_path.is_dir():
            raise FileNotFoundError(f"Experiment directory not found: {exp_path}")

        # 1. Load frozen preprocessor
        prep = Preprocessor.load(exp_path)

        # 2. Load frozen model weights
        model_path = exp_path / model_filename
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        model = joblib.load(model_path)

        # 3. Optional calibration artifact
        calibrator = None
        score_type = "tree_vote_fraction"
        if use_calibration:
            calib_path = exp_path / "calibration_report.json"
            if calib_path.exists():
                calibrator = PlattCalibrator.load(exp_path)
                score_type = "calibrated_probability_platt"

        return cls(
            preprocessor=prep,
            model=model,
            calibrator=calibrator,
            experiment_id=exp_path.name,
            score_type=score_type,
        )

    def predict_score(self, X_raw: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Produce continuous attack risk scores S_t in [0.0, 1.0] without modifying model state."""
        # Preprocess features
        if isinstance(X_raw, pd.DataFrame):
            X_scaled = self.preprocessor.transform(X_raw)
        else:
            X_scaled = X_raw

        # Model continuous score
        if hasattr(self.model, "predict_proba"):
            scores = self.model.predict_proba(X_scaled)
            # If 2D probability array, extract class 1 (attack)
            if hasattr(scores, "ndim") and scores.ndim == 2:
                scores = scores[:, 1]
        elif hasattr(self.model, "predict"):
            scores = self.model.predict(X_scaled)
        else:
            raise TypeError(f"Loaded model {type(self.model)} has no predict or predict_proba method.")

        scores = np.asarray(scores, dtype=np.float32)

        # Apply calibration only if explicitly loaded
        if self.calibrator is not None:
            scores = self.calibrator.predict_proba(scores)

        # Ensure valid [0.0, 1.0] range
        scores = np.clip(scores, 0.0, 1.0)
        return scores

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "feature_names": list(self.preprocessor.features),
            "score_type": self.score_type,
            "calibrated": self.calibrator is not None,
            "read_only": True,
        }
