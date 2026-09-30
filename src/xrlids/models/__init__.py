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

__all__ = [
    "RandomForestDetector",
    "RandomForestError",
    "DEFAULT_RF_PARAMS",
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
