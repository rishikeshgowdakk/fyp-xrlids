"""Detectors: Random Forest, supervised LSTM, and score fusion."""

from xrlids.models.fusion import FusionError, FusionResult, align_scores, fuse, fuse_scores
from xrlids.models.lstm import (
    DEFAULT_LSTM_PARAMS,
    LSTMDetector,
    SequenceError,
    SequenceSet,
    assert_no_boundary_crossing,
    build_sequences,
)
from xrlids.models.random_forest import DEFAULT_RF_PARAMS, RandomForestDetector, RandomForestError
from xrlids.models.xgboost_detector import DEFAULT_XGB_PARAMS, XGBoostDetector, XGBoostError
from xrlids.models.registry import (
    DEFAULT_MODEL_REGISTRY,
    InferenceResult,
    ModelMetadata,
    ModelRegistry,
    ModelRegistryError,
    ValidationError,
)

__all__ = [
    "RandomForestDetector",
    "RandomForestError",
    "DEFAULT_RF_PARAMS",
    "XGBoostDetector",
    "XGBoostError",
    "DEFAULT_XGB_PARAMS",
    "ModelRegistry",
    "ModelMetadata",
    "ModelRegistryError",
    "ValidationError",
    "InferenceResult",
    "DEFAULT_MODEL_REGISTRY",
    "LSTMDetector",
    "SequenceSet",
    "SequenceError",
    "build_sequences",
    "assert_no_boundary_crossing",
    "DEFAULT_LSTM_PARAMS",
    "fuse",
    "fuse_scores",
    "align_scores",
    "FusionResult",
    "FusionError",
]
