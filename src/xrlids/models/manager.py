"""Central Model Manager for XRL-IDARS (Phase 5).

Loads registered champion models (Random Forest or XGBoost) alongside train-fitted
preprocessors, validates feature schemas, and executes high-performance flow inference.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time
from typing import Any, Mapping

import numpy as np
import pandas as pd

from xrlids.features.definitions import R10_FEATURES
from xrlids.features.validator import FeatureSchemaValidator, FeatureValidationError
from xrlids.models.random_forest import RandomForestDetector
from xrlids.models.xgboost_detector import XGBoostDetector
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REGISTRY_PATH = REPO_ROOT / "models" / "registry" / "champion_registry.json"


@dataclass
class FlowInferenceResult:
    """Standardized inference output for an individual network flow."""

    flow_id: str
    prediction: int  # 0 = Benign, 1 = Attack
    prediction_label: str  # "BENIGN" or "ATTACK"
    attack_score: float  # Continuous score P(ATTACK) in [0.0, 1.0]
    raw_probabilities: dict[str, float]
    model_name: str
    model_type: str  # "rf" or "xgboost"
    feature_contract: str  # "R10"
    features_validated: dict[str, float]
    inference_time_ms: float
    decision_threshold: float = 0.50

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelManager:
    """Manages active ML detectors and execution of verified flow inference."""

    def __init__(
        self,
        registry_path: Path | str | None = None,
        repo_root: Path | str | None = None,
        force_model_type: str | None = None,
    ) -> None:
        self.repo_root = Path(repo_root or REPO_ROOT)
        self.registry_path = Path(registry_path or DEFAULT_REGISTRY_PATH)
        self.force_model_type = force_model_type

        self.validator = FeatureSchemaValidator("R10")
        self.champion_metadata: dict[str, Any] = {}
        self.model: Any = None
        self.preprocessor: Preprocessor | None = None
        self.model_name: str = "Unknown"
        self.model_type: str = "rf"
        self.decision_threshold: float = 0.50

        self._load_champion_and_preprocessor()

    def _load_champion_and_preprocessor(self) -> None:
        """Load champion configuration and instantiate model and preprocessor."""
        if self.registry_path.exists():
            try:
                registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
                self.champion_metadata = registry.get("champion", {})
            except Exception as e:
                logger.warning("Could not read champion registry from %s: %s", self.registry_path, e)

        model_type = (
            self.force_model_type
            or self.champion_metadata.get("model_type")
            or "rf"
        ).lower()
        self.model_type = model_type
        self.decision_threshold = float(self.champion_metadata.get("decision_threshold", 0.50))

        # 1. Load Preprocessor
        preproc_rel = self.champion_metadata.get(
            "preprocessor_path",
            "results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib",
        )
        preproc_path = self.repo_root / preproc_rel
        if preproc_path.is_file():
            self.preprocessor = Preprocessor.load(preproc_path.parent)
        elif (preproc_path.parent / "preprocessor.joblib").is_file():
            self.preprocessor = Preprocessor.load(preproc_path.parent)
        else:
            logger.warning("Preprocessor not found at %s; unscaled inference will be used", preproc_path)

        # 2. Load Model
        if model_type in ("xgboost", "xgb"):
            xgb_path = self.repo_root / self.champion_metadata.get("model_path", "models/xgboost/xgboost_cicids2017.json")
            if not xgb_path.exists():
                xgb_path = self.repo_root / "models" / "xgboost" / "xgboost_cicids2017.json"
            self.model = XGBoostDetector.load(xgb_path)
            self.model_name = "XGBoost Champion"
            self.model_type = "xgboost"
        else:
            rf_path = self.repo_root / self.champion_metadata.get("model_path", "models/rf/random_forest_cicids2017.joblib")
            if not rf_path.exists():
                rf_path = self.repo_root / "models" / "rf" / "random_forest_cicids2017.joblib"
            import joblib
            self.model = joblib.load(rf_path)
            self.model_name = "Random Forest Champion"
            self.model_type = "rf"

        logger.info("ModelManager initialized with model '%s' (%s)", self.model_name, self.model_type)

    @property
    def features(self) -> list[str]:
        """Expected feature column names for the model."""
        return list(R10_FEATURES)

    def predict_flow(
        self,
        features: Mapping[str, Any],
        flow_id: str | None = None,
    ) -> FlowInferenceResult:
        """Run single-flow inference under strict contract validation."""
        t0 = time.perf_counter()

        # 1. Validate Schema
        valid_res = self.validator.validate(dict(features))
        row_df = valid_res.dataframe[list(R10_FEATURES)]
        feat_dict = dict(row_df.iloc[0])

        # 3. Transform via fitted Preprocessor
        if self.preprocessor is not None:
            transformed_df = self.preprocessor.transform(row_df)
        else:
            transformed_df = row_df

        # 4. Predict Attack Probability
        score_arr = self.model.predict_proba(transformed_df)
        attack_score = float(score_arr[0])
        pred_label = 1 if attack_score >= self.decision_threshold else 0
        label_str = "ATTACK" if pred_label == 1 else "BENIGN"

        t1 = time.perf_counter()
        infer_time_ms = (t1 - t0) * 1000.0

        return FlowInferenceResult(
            flow_id=flow_id or f"flow-{int(time.time()*1000)}",
            prediction=pred_label,
            prediction_label=label_str,
            attack_score=attack_score,
            raw_probabilities={
                "BENIGN": 1.0 - attack_score,
                "ATTACK": attack_score,
            },
            model_name=self.model_name,
            model_type=self.model_type,
            feature_contract="R10",
            features_validated=feat_dict,
            inference_time_ms=infer_time_ms,
            decision_threshold=self.decision_threshold,
        )

    def predict_batch(self, features_df: pd.DataFrame) -> np.ndarray:
        """Predict continuous attack probabilities across a batch of flows."""
        valid_res = self.validator.validate(features_df)
        df_clean = valid_res.dataframe[list(R10_FEATURES)]
        if self.preprocessor is not None:
            df_trans = self.preprocessor.transform(df_clean)
        else:
            df_trans = df_clean
        return self.model.predict_proba(df_trans)
