"""Unified TreeSHAP Explainability Service for XRL-IDARS (Phase 6).

Provides real-time local additive feature attributions for both Random Forest
and XGBoost detection models under strict feature contract validation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
import shap

from xrlids.features.definitions import R10_FEATURES
from xrlids.features.validator import FeatureSchemaValidator
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class FeatureAttribution:
    """Attribution metadata for a single feature."""

    feature: str
    value: float
    shap_attribution: float
    direction: str  # "INCREASES_THREAT" | "DECREASES_THREAT" | "NEUTRAL"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExplanationResult:
    """Local explanation result for a single network flow."""

    explainer_model: str
    model_type: str
    base_value: float
    top_features: list[dict[str, Any]]
    attributions: list[dict[str, Any]]
    explanation_time_ms: float
    scientific_notices: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TreeSHAPExplainer:
    """Production-grade local explainer utilizing Lundberg & Lee's TreeSHAP."""

    def __init__(
        self,
        model: Any,
        feature_names: Sequence[str] | None = None,
        preprocessor: Preprocessor | None = None,
    ) -> None:
        self.preprocessor = preprocessor
        self.feature_names = list(feature_names or R10_FEATURES)
        self.validator = FeatureSchemaValidator("R10")

        # Recursively unwrap model if passed as manager or detector wrapper
        underlying = model
        while hasattr(underlying, "model") and getattr(underlying, "model") is not None:
            underlying = getattr(underlying, "model")
        if underlying is None:
            raise ValueError("Model passed to TreeSHAPExplainer is not fitted or is None")

        self.underlying_model = underlying
        self.model_type = "xgboost" if "xgb" in type(underlying).__module__.lower() else "rf"
        self.explainer = shap.TreeExplainer(self.underlying_model)

    def explain_flow(
        self,
        features: Mapping[str, Any],
        flow_id: str | None = None,
    ) -> ExplanationResult:
        """Compute exact local TreeSHAP attributions for a single flow."""
        import time
        t0 = time.perf_counter()

        valid_res = self.validator.validate(dict(features))
        row_df = valid_res.dataframe[self.feature_names]

        # Apply preprocessing if available
        if self.preprocessor is not None:
            X_eval = self.preprocessor.transform(row_df).to_numpy(dtype=float)
        else:
            X_eval = row_df.to_numpy(dtype=float)

        raw_shap = self.explainer.shap_values(X_eval)

        # Parse attack class contributions
        if isinstance(raw_shap, list) and len(raw_shap) >= 2:
            # Scikit-learn RF binary classifier: list of [class_0, class_1]
            attack_contribs = np.asarray(raw_shap[1]).ravel()
        elif hasattr(raw_shap, "ndim") and raw_shap.ndim == 3 and raw_shap.shape[2] >= 2:
            attack_contribs = raw_shap[0, :, 1].ravel()
        else:
            # XGBoost binary classification: 1D or 2D array of log-odds / margin contributions
            attack_contribs = np.asarray(raw_shap).ravel()

        # Parse base value (expected value)
        base_val = 0.50
        if hasattr(self.explainer, "expected_value"):
            exp_val = self.explainer.expected_value
            if hasattr(exp_val, "__len__") and len(exp_val) >= 2:
                base_val = float(exp_val[1])
            elif hasattr(exp_val, "__len__") and len(exp_val) == 1:
                base_val = float(exp_val[0])
            else:
                base_val = float(exp_val)

        feature_records: list[dict[str, Any]] = []
        for feat, contrib, val in zip(self.feature_names, attack_contribs, row_df.iloc[0]):
            c_val = float(contrib)
            direction = (
                "INCREASES_THREAT"
                if c_val > 1e-5
                else ("DECREASES_THREAT" if c_val < -1e-5 else "NEUTRAL")
            )
            feature_records.append({
                "feature": feat,
                "value": round(float(val), 4),
                "shap_attribution": round(c_val, 5),
                "direction": direction,
            })

        feature_records.sort(key=lambda x: abs(x["shap_attribution"]), reverse=True)
        attributions = [
            {
                "feature": f["feature"],
                "attribution": f["shap_attribution"],
                "shap_attribution": f["shap_attribution"],
                "value": f["value"],
                "direction": f["direction"],
            }
            for f in feature_records
        ]

        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0

        model_desc = f"{'XGBoost' if self.model_type == 'xgboost' else 'Random Forest'} Detector (TreeExplainer)"
        notices = [
            "Local feature attributions computed via exact TreeSHAP algorithm (Lundberg & Lee, 2017).",
            "Positive attribution indicates feature value drives score toward ATTACK; negative toward BENIGN.",
            "Attributions reflect the primary ML detector path and are distinct from rule and RL decisions.",
        ]

        return ExplanationResult(
            explainer_model=model_desc,
            model_type=self.model_type,
            base_value=round(base_val, 4),
            top_features=feature_records,
            attributions=attributions,
            explanation_time_ms=elapsed_ms,
            scientific_notices=notices,
        )
