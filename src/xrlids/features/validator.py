"""Feature schema and input validation engine for XRL-IDARS.

Guarantees:
1. Strict contract enforcement for R10 (10 canonical features) and R4 (degraded).
2. Exact column ordering matching model training signatures.
3. Finite value enforcement: rejects NaN, +inf, -inf without silent zero-filling.
4. Target and metadata leakage prevention: ensures IP addresses, ports, timestamps,
   and labels never enter machine learning feature vectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.features.definitions import R4_FEATURES, R10_FEATURES

PROHIBITED_METADATA_COLUMNS: set[str] = {
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "src_port",
    "dst_port",
    "source_port",
    "destination_port",
    "protocol",
    "timestamp",
    "time",
    "label",
    "binary_label",
    "attack_cat",
    "ground_truth",
    "is_attack",
    "flow_id",
}


class FeatureValidationError(ValueError):
    """Raised when incoming features violate contract or finite value constraints."""


@dataclass(frozen=True)
class ValidationResult:
    """Result of feature validation."""

    is_valid: bool
    contract: str
    feature_names: list[str]
    feature_matrix: np.ndarray
    dataframe: pd.DataFrame
    dropped_metadata: dict[str, Any]


class FeatureSchemaValidator:
    """Production-grade feature validator for live and replay inference."""

    CONTRACT_SCHEMAS: dict[str, tuple[str, ...]] = {
        "R10": R10_FEATURES,
        "R4": R4_FEATURES,
    }

    def __init__(self, contract: str = "R10") -> None:
        contract_key = contract.upper().strip()
        if contract_key not in self.CONTRACT_SCHEMAS:
            raise FeatureValidationError(
                f"Unknown feature contract '{contract}'. Supported: {list(self.CONTRACT_SCHEMAS.keys())}"
            )
        self.contract = contract_key
        self.expected_features = self.CONTRACT_SCHEMAS[contract_key]

    def validate(
        self,
        features: dict[str, Any] | pd.Series | pd.DataFrame | np.ndarray,
    ) -> ValidationResult:
        """Validate input features against contract schema and numerical constraints.

        Parameters
        ----------
        features: dict, Series, DataFrame, or 2D array
            Incoming feature observation(s).

        Returns
        -------
        ValidationResult with validated 2D float32 array and clean DataFrame.

        Raises
        ------
        FeatureValidationError if schema is violated or non-finite values are found.
        """
        dropped_meta: dict[str, Any] = {}

        # 1. Normalize input to DataFrame
        if isinstance(features, dict):
            # Check for prohibited metadata and isolate it
            clean_dict = {}
            for k, v in features.items():
                if k.lower() in PROHIBITED_METADATA_COLUMNS:
                    dropped_meta[k] = v
                else:
                    clean_dict[k] = v
            df = pd.DataFrame([clean_dict])
        elif isinstance(features, pd.Series):
            clean_dict = {}
            for k, v in features.to_dict().items():
                if str(k).lower() in PROHIBITED_METADATA_COLUMNS:
                    dropped_meta[str(k)] = v
                else:
                    clean_dict[str(k)] = v
            df = pd.DataFrame([clean_dict])
        elif isinstance(features, pd.DataFrame):
            df = features.copy()
            # Drop metadata columns from ML frame
            for col in list(df.columns):
                if str(col).lower() in PROHIBITED_METADATA_COLUMNS:
                    dropped_meta[str(col)] = df[col].tolist()
                    df = df.drop(columns=[col])
        elif isinstance(features, np.ndarray):
            arr = np.asarray(features, dtype=np.float32)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            if arr.shape[1] != len(self.expected_features):
                raise FeatureValidationError(
                    f"Array shape mismatch: expected {len(self.expected_features)} features, got {arr.shape[1]}"
                )
            df = pd.DataFrame(arr, columns=list(self.expected_features))
        else:
            raise FeatureValidationError(f"Unsupported features type: {type(features)}")

        # 2. Check for missing contract columns (NEVER silently replace with 0)
        missing = [col for col in self.expected_features if col not in df.columns]
        if missing:
            raise FeatureValidationError(
                f"Missing required contract features for {self.contract}: {missing}. "
                f"Expected exact columns: {list(self.expected_features)}"
            )

        # 3. Enforce exact column ordering
        df_ordered = df[list(self.expected_features)].copy()

        # 4. Check for non-finite values (NaN, +inf, -inf)
        for col in self.expected_features:
            vals = pd.to_numeric(df_ordered[col], errors="coerce")
            if vals.isna().any():
                raise FeatureValidationError(
                    f"Invalid non-finite or non-numeric value (NaN) encountered in feature '{col}'."
                )
            if np.isinf(vals).any():
                raise FeatureValidationError(
                    f"Invalid infinite value (+inf/-inf) encountered in feature '{col}'."
                )
            df_ordered[col] = vals.astype(np.float32)

        feature_matrix = df_ordered.to_numpy(dtype=np.float32)

        return ValidationResult(
            is_valid=True,
            contract=self.contract,
            feature_names=list(self.expected_features),
            feature_matrix=feature_matrix,
            dataframe=df_ordered,
            dropped_metadata=dropped_meta,
        )
