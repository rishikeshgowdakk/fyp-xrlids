"""Multiclass Attack Family Classification Subsystem (Priority 4).

Implements multiclass attack attribution for XRL-IDARS:
1. Classifies threats into canonical attack families (DoS, DDoS, PortScan, BruteForce, Bot, Infiltration, Web).
2. Provides calibrated confidence distributions over all candidate families.
3. Implements strict fallback to 'UNKNOWN' whenever classification confidence is below 0.40.
4. Operates in parallel with the Protocol Rule Engine without violating rule independence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence
import joblib
import numpy as np

from xrlids.features.definitions import R10_FEATURES
from xrlids.features.validator import FeatureSchemaValidator
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

CANONICAL_ATTACK_FAMILIES: tuple[str, ...] = (
    "BENIGN",
    "DoS",
    "DDoS",
    "PortScan",
    "BruteForce",
    "Bot",
    "Infiltration",
    "Web",
)

DEFAULT_CONFIDENCE_THRESHOLD: float = 0.40


@dataclass(frozen=True)
class MulticlassPrediction:
    """Structured multiclass attack family inference result."""

    predicted_family: str
    confidence: float
    is_known_family: bool
    family_probabilities: dict[str, float]
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicted_family": self.predicted_family,
            "confidence": round(self.confidence, 4),
            "is_known_family": self.is_known_family,
            "confidence_threshold": self.confidence_threshold,
            "family_probabilities": {k: round(v, 4) for k, v in self.family_probabilities.items()},
        }


class MulticlassAttackClassifier:
    """Random Forest / XGBoost based multiclass attack family classifier."""

    def __init__(
        self,
        model: Any = None,
        classes: Sequence[str] | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        feature_names: Sequence[str] = R10_FEATURES,
    ) -> None:
        self.model = model
        self.classes = tuple(classes if classes is not None else CANONICAL_ATTACK_FAMILIES)
        self.confidence_threshold = confidence_threshold
        self.feature_names = tuple(feature_names)
        self.validator = FeatureSchemaValidator("R10" if len(feature_names) == 10 else "R4")

    def fit(self, X: np.ndarray, y: Sequence[str] | np.ndarray) -> "MulticlassAttackClassifier":
        """Train classifier on feature matrix X and string attack family labels y."""
        from sklearn.ensemble import RandomForestClassifier
        if self.model is None:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=16,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
        unique_classes = sorted(list(set(y)))
        self.classes = tuple(unique_classes)
        self.model.fit(X, y)
        return self

    def predict_family(
        self,
        features: Mapping[str, float] | np.ndarray,
        confidence_threshold: float | None = None,
    ) -> MulticlassPrediction:
        """Infer attack family with calibrated confidence and UNKNOWN fallback."""
        thresh = confidence_threshold if confidence_threshold is not None else self.confidence_threshold

        # Extract ordered feature vector
        if isinstance(features, Mapping):
            self.validator.validate(dict(features))
            x_vec = np.array([[float(features[f]) for f in self.feature_names]], dtype=np.float32)
        else:
            x_vec = np.asarray(features, dtype=np.float32)
            if x_vec.ndim == 1:
                x_vec = x_vec.reshape(1, -1)

        if self.model is None:
            # Fallback when no trained model loaded
            return MulticlassPrediction(
                predicted_family="UNKNOWN",
                confidence=0.0,
                is_known_family=False,
                family_probabilities={c: 0.0 for c in self.classes},
                confidence_threshold=thresh,
            )

        probs = self.model.predict_proba(x_vec)[0]
        model_classes = list(getattr(self.model, "classes_", self.classes))
        prob_dict = {str(c): float(p) for c, p in zip(model_classes, probs)}

        # Determine top prediction
        best_class = max(prob_dict, key=prob_dict.get)  # type: ignore[arg-type]
        best_prob = prob_dict[best_class]

        # Apply confidence threshold fallback
        if best_prob < thresh:
            return MulticlassPrediction(
                predicted_family="UNKNOWN",
                confidence=best_prob,
                is_known_family=False,
                family_probabilities=prob_dict,
                confidence_threshold=thresh,
            )

        return MulticlassPrediction(
            predicted_family=best_class,
            confidence=best_prob,
            is_known_family=(best_class != "UNKNOWN"),
            family_probabilities=prob_dict,
            confidence_threshold=thresh,
        )

    def predict_batch(
        self,
        X: np.ndarray,
        confidence_threshold: float | None = None,
    ) -> list[MulticlassPrediction]:
        """Perform vectorized batch inference across multiple feature rows."""
        thresh = confidence_threshold if confidence_threshold is not None else self.confidence_threshold
        X_arr = np.asarray(X, dtype=np.float32)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)

        if self.model is None:
            return [
                MulticlassPrediction(
                    predicted_family="UNKNOWN",
                    confidence=0.0,
                    is_known_family=False,
                    family_probabilities={c: 0.0 for c in self.classes},
                    confidence_threshold=thresh,
                )
                for _ in range(len(X_arr))
            ]

        all_probs = self.model.predict_proba(X_arr)
        model_classes = list(getattr(self.model, "classes_", self.classes))

        results = []
        for probs in all_probs:
            prob_dict = {str(c): float(p) for c, p in zip(model_classes, probs)}
            best_class = max(prob_dict, key=prob_dict.get)  # type: ignore[arg-type]
            best_prob = prob_dict[best_class]
            if best_prob < thresh:
                results.append(
                    MulticlassPrediction(
                        predicted_family="UNKNOWN",
                        confidence=best_prob,
                        is_known_family=False,
                        family_probabilities=prob_dict,
                        confidence_threshold=thresh,
                    )
                )
            else:
                results.append(
                    MulticlassPrediction(
                        predicted_family=best_class,
                        confidence=best_prob,
                        is_known_family=(best_class != "UNKNOWN"),
                        family_probabilities=prob_dict,
                        confidence_threshold=thresh,
                    )
                )
        return results

    def save(self, model_path: Path | str) -> None:
        """Serialize trained multiclass classifier and metadata to disk."""
        path = Path(model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "model": self.model,
            "classes": self.classes,
            "confidence_threshold": self.confidence_threshold,
            "feature_names": self.feature_names,
        }
        joblib.dump(artifact, path, compress=3)
        logger.info("Saved MulticlassAttackClassifier to %s", path)

    @classmethod
    def load(cls, model_path: Path | str) -> "MulticlassAttackClassifier":
        """Load trained classifier from disk."""
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Multiclass model artifact not found: {path}")
        artifact = joblib.load(path)
        return cls(
            model=artifact["model"],
            classes=artifact["classes"],
            confidence_threshold=artifact.get("confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD),
            feature_names=artifact.get("feature_names", R10_FEATURES),
        )
