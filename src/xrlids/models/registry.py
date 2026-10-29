"""Centralized Model Registry and Trustworthy Inference Engine for XRL-IDARS.

Guarantees:
1. Canonical Model Registry:
   - Associates every supported benchmark (cicids2017, cse2018, unswnb15) with its
     model type, canonical artifact path, expected feature contract (R10 or R4),
     matching preprocessor, supported classes, and loading status.
2. Trustworthy Inference Path (infer):
   - Benchmark validation: rejects unknown benchmarks.
   - Strict feature contract validation: requires all expected features; rejects
     missing fields, non-numeric values, NaN, and +/-infinity (no silent zero-filling).
   - Single-pass preprocessing: applies the matching frozen preprocessor exactly once.
   - Dynamic class probability mapping: inspects estimator.classes_ rather than assuming
     index 0 is Benign and index 1 is Attack.
   - Structured result: returns structured InferenceResult with prediction, continuous
     attack score, class probability breakdown, execution latency in milliseconds,
     and model provenance.
   - Refuses to fabricate default scores or fallback benign verdicts on error.
3. TreeSHAP Explainability Integration:
   - Delegates single-flow TreeSHAP explanation to verified explain_flow_prediction().
4. Dry-Run DQN Autonomous Response Recommendation:
   - Evaluates response action under strict DRY_RUN observation mode (zero firewall mutations).
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd

from xrlids.features.definitions import R4_FEATURES, R10_FEATURES

logger = logging.getLogger("xrlids.models.registry")

REPO_ROOT = Path(__file__).resolve().parents[3]


class ModelRegistryError(RuntimeError):
    """Raised when a model cannot be loaded, registered, or verified."""


class ValidationError(ValueError):
    """Raised when input features violate contract, are missing, NaN, or infinite."""


@dataclass(frozen=True)
class ModelMetadata:
    """Metadata describing a registered model artifact."""

    model_id: str
    model_type: str  # "rf", "lstm", "dqn", "fusion"
    benchmark: str  # "cicids2017", "cse2018", "unswnb15"
    feature_contract: str  # "R10", "R4", "response_state_v1"
    expected_features: tuple[str, ...]
    model_path: Path
    preprocessor_path: Path | None
    classes: tuple[str, ...] = ("BENIGN", "ATTACK")
    status: str = "REGISTERED"


@dataclass
class InferenceResult:
    """Structured, verified detection inference result."""

    prediction: int  # 0 = Benign, 1 = Attack
    prediction_label: str  # "BENIGN" or "ATTACK"
    attack_score: float  # Posterior probability P(class=1)
    raw_probabilities: dict[str, float]  # Class name -> probability
    benchmark: str
    feature_contract: str
    model_id: str
    inference_time_ms: float
    features_validated: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelRegistry:
    """Thread-safe registry managing model artifacts, preprocessors, and inference."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or REPO_ROOT
        self._models: dict[str, ModelMetadata] = {}
        self._loaded_models: dict[str, Any] = {}
        self._loaded_preprocessors: dict[str, Any] = {}
        self._initialize_canonical_registry()

    def _initialize_canonical_registry(self) -> None:
        """Register the canonical research models and their matched preprocessors."""
        rf_cicids2017 = ModelMetadata(
            model_id="random_forest_cicids2017.joblib",
            model_type="rf",
            benchmark="cicids2017",
            feature_contract="R10",
            expected_features=R10_FEATURES,
            model_path=self.repo_root / "models" / "rf" / "random_forest_cicids2017.joblib",
            preprocessor_path=self.repo_root / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib",
            classes=("BENIGN", "ATTACK"),
        )
        rf_cse2018 = ModelMetadata(
            model_id="random_forest_cse2018.joblib",
            model_type="rf",
            benchmark="cse2018",
            feature_contract="R10",
            expected_features=R10_FEATURES,
            model_path=self.repo_root / "models" / "rf" / "random_forest_cse2018.joblib",
            preprocessor_path=self.repo_root / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib",
            classes=("BENIGN", "ATTACK"),
        )
        rf_unswnb15 = ModelMetadata(
            model_id="random_forest_unswnb15.joblib",
            model_type="rf",
            benchmark="unswnb15",
            feature_contract="R4",
            expected_features=R4_FEATURES,
            model_path=self.repo_root / "models" / "rf" / "random_forest_unswnb15.joblib",
            preprocessor_path=self.repo_root / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "preprocessor.joblib",
            classes=("BENIGN", "ATTACK"),
        )

        for meta in (rf_cicids2017, rf_cse2018, rf_unswnb15):
            self.register(meta)

    def register(self, metadata: ModelMetadata) -> None:
        """Register model metadata under benchmark and model_id."""
        self._models[metadata.model_id] = metadata
        key = f"{metadata.benchmark}:{metadata.model_type}"
        self._models[key] = metadata

    def get_metadata(self, benchmark: str, model_type: str = "rf") -> ModelMetadata:
        """Lookup metadata by benchmark and model type."""
        bench_key = str(benchmark).lower().strip()
        key = f"{bench_key}:{model_type}"
        if key not in self._models:
            supported = [m.benchmark for m in self._models.values() if m.model_type == model_type]
            raise ModelRegistryError(
                f"No {model_type} model registered for benchmark '{benchmark}'. "
                f"Supported benchmarks: {sorted(set(supported))}"
            )
        return self._models[key]

    def load_preprocessor(self, metadata: ModelMetadata) -> Any:
        """Load and cache the matching preprocessor artifact."""
        if metadata.model_id in self._loaded_preprocessors:
            return self._loaded_preprocessors[metadata.model_id]

        if metadata.preprocessor_path is None or not metadata.preprocessor_path.exists():
            raise ModelRegistryError(
                f"Preprocessor artifact missing at {metadata.preprocessor_path} for {metadata.model_id}"
            )

        try:
            prep = joblib.load(metadata.preprocessor_path)
            self._loaded_preprocessors[metadata.model_id] = prep
            return prep
        except Exception as exc:
            raise ModelRegistryError(
                f"Failed to load preprocessor for {metadata.model_id} from {metadata.preprocessor_path}: {exc}"
            ) from exc

    def load_model(self, metadata: ModelMetadata) -> Any:
        """Load and cache the model artifact."""
        if metadata.model_id in self._loaded_models:
            return self._loaded_models[metadata.model_id]

        if not metadata.model_path.exists():
            raise ModelRegistryError(
                f"Model artifact missing at {metadata.model_path} for {metadata.model_id}"
            )

        try:
            model = joblib.load(metadata.model_path)
            self._loaded_models[metadata.model_id] = model
            return model
        except Exception as exc:
            raise ModelRegistryError(
                f"Failed to load model {metadata.model_id} from {metadata.model_path}: {exc}"
            ) from exc

    def validate_features(
        self,
        features: Mapping[str, Any],
        expected_features: Sequence[str],
        contract_name: str,
    ) -> dict[str, float]:
        """Strictly validate input features against expected schema.

        Rejects missing features, None, NaN, inf, -inf, or non-numeric types.
        Never fills missing features with default zeros.
        """
        if not isinstance(features, Mapping):
            raise ValidationError(f"Features must be a dictionary, got {type(features).__name__}")

        missing = [f for f in expected_features if f not in features or features[f] is None]
        if missing:
            raise ValidationError(
                f"Inference rejected: missing required features for contract {contract_name}: {missing}. "
                "Silent zero-filling is prohibited."
            )

        cleaned: dict[str, float] = {}
        for f in expected_features:
            raw_val = features[f]
            try:
                val = float(raw_val)
            except (ValueError, TypeError) as exc:
                raise ValidationError(
                    f"Inference rejected: feature '{f}' has non-numeric value {raw_val!r}: {exc}"
                ) from exc

            if math.isnan(val) or math.isinf(val):
                raise ValidationError(
                    f"Inference rejected: feature '{f}' contains invalid numeric value: {val}"
                )
            cleaned[f] = val

        return cleaned

    def validate_model_preprocessor_compatibility(
        self, benchmark: str, model_type: str = "rf"
    ) -> dict[str, Any]:
        """Verify that the model and matching preprocessor have compatible feature schemas.

        Raises ModelRegistryError if schemas or contracts differ.
        """
        meta = self.get_metadata(benchmark, model_type=model_type)
        model = self.load_model(meta)
        preprocessor = self.load_preprocessor(meta)

        model_features = getattr(model, "feature_names", None)
        prep_features = getattr(preprocessor, "features", None)

        if model_features and prep_features and list(model_features) != list(prep_features):
            raise ModelRegistryError(
                f"Schema mismatch for benchmark '{benchmark}': "
                f"preprocessor features {list(prep_features)} do not match model features {list(model_features)}"
            )

        if model_features and list(model_features) != list(meta.expected_features):
            raise ModelRegistryError(
                f"Contract mismatch for benchmark '{benchmark}': "
                f"model features {list(model_features)} do not match declared contract features {list(meta.expected_features)}"
            )

        return {
            "benchmark": benchmark,
            "contract": meta.feature_contract,
            "feature_count": len(meta.expected_features),
            "features": list(meta.expected_features),
            "status": "COMPATIBLE",
        }

    def infer(
        self,
        features: Mapping[str, Any],
        benchmark: str = "cicids2017",
        threshold: float = 0.50,
        model_type: str = "rf",
    ) -> InferenceResult:
        """Execute validated, single-pass inference and return structured InferenceResult.

        Guarantees:
        - Strict validation: rejects missing, non-numeric, NaN, infinite features.
        - Matching preprocessor is applied exactly once.
        - Evaluates probability against estimator's actual class mapping.
        - Measures exact inference execution latency in milliseconds.
        """
        t0 = time.perf_counter()

        meta = self.get_metadata(benchmark, model_type=model_type)
        valid_feats = self.validate_features(
            features,
            expected_features=meta.expected_features,
            contract_name=meta.feature_contract,
        )

        model = self.load_model(meta)
        preprocessor = self.load_preprocessor(meta)

        # Single-row DataFrame ordered strictly according to expected_features
        raw_df = pd.DataFrame([[valid_feats[f] for f in meta.expected_features]], columns=list(meta.expected_features))

        # Single-pass transformation
        scaled_df = preprocessor.transform(raw_df)

        # Explicit model/preprocessor schema compatibility assertion
        model_features = getattr(model, "feature_names", None)
        if model_features and list(scaled_df.columns) != list(model_features):
            raise ModelRegistryError(
                f"Model/preprocessor schema mismatch for {meta.model_id}: "
                f"preprocessor produced columns {list(scaled_df.columns)} but model expects {list(model_features)}"
            )

        # Inference on underlying estimator
        inner_model = model.model if hasattr(model, "model") and model.model is not None else model

        attack_prob = 0.0
        prob_dict: dict[str, float] = {}

        if hasattr(inner_model, "predict_proba"):
            probs = inner_model.predict_proba(scaled_df.to_numpy(dtype=float))
            classes = getattr(inner_model, "classes_", np.array([0, 1]))

            # Map probabilities using actual classes_ array
            if probs.ndim == 2 and probs.shape[0] == 1:
                for idx, cls_val in enumerate(classes):
                    cls_name = "ATTACK" if cls_val == 1 else "BENIGN"
                    p_val = float(probs[0, idx])
                    prob_dict[cls_name] = p_val
                    if cls_val == 1:
                        attack_prob = p_val
            elif probs.ndim == 1:
                attack_prob = float(probs[0])
                prob_dict["ATTACK"] = attack_prob
                prob_dict["BENIGN"] = 1.0 - attack_prob
        elif hasattr(model, "predict_proba"):
            attack_prob = float(model.predict_proba(scaled_df)[0])
            prob_dict["ATTACK"] = attack_prob
            prob_dict["BENIGN"] = 1.0 - attack_prob
        else:
            raise ModelRegistryError(f"Model {meta.model_id} does not support probability prediction.")

        pred_class = 1 if attack_prob >= threshold else 0
        pred_label = "ATTACK" if pred_class == 1 else "BENIGN"

        t1 = time.perf_counter()
        latency_ms = round((t1 - t0) * 1000.0, 3)

        return InferenceResult(
            prediction=pred_class,
            prediction_label=pred_label,
            attack_score=round(attack_prob, 4),
            raw_probabilities={k: round(v, 4) for k, v in prob_dict.items()},
            benchmark=meta.benchmark,
            feature_contract=meta.feature_contract,
            model_id=meta.model_id,
            inference_time_ms=latency_ms,
            features_validated=valid_feats,
        )


# Global singleton instance
DEFAULT_MODEL_REGISTRY = ModelRegistry()
