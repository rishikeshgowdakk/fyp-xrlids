"""Feature engineering: definitions, registry, computation and validation."""

from xrlids.features.compute import (
    FeatureMatrix,
    FeatureValidationError,
    build_feature_matrix,
    compute_features,
    extract_semantics,
    validate_feature_matrix,
)
from xrlids.features.definitions import FEATURES, FeatureSpec, feature_spec
from xrlids.features.registry import FeatureRegistry, load_feature_registry

__all__ = [
    "FEATURES",
    "FeatureSpec",
    "feature_spec",
    "FeatureRegistry",
    "load_feature_registry",
    "FeatureMatrix",
    "FeatureValidationError",
    "build_feature_matrix",
    "compute_features",
    "extract_semantics",
    "validate_feature_matrix",
]
