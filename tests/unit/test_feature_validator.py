"""Unit tests for FeatureSchemaValidator.

Verifies:
1. Valid R10 feature vectors pass validation with correct column ordering.
2. Missing contract columns raise FeatureValidationError (never silently zero-filled).
3. Non-finite values (NaN, +inf, -inf) are strictly rejected.
4. Prohibited network metadata (IP, port, timestamp, label) is automatically isolated
   and stripped from the ML feature matrix.
5. Contract R4 validation for degraded schemas.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.features.definitions import R4_FEATURES, R10_FEATURES
from xrlids.features.validator import FeatureSchemaValidator, FeatureValidationError


@pytest.fixture
def valid_r10_dict() -> dict[str, float]:
    return {
        "flow_duration_ms": 1200.5,
        "flow_packets_per_s": 25.4,
        "flow_bytes_per_s": 15400.0,
        "packet_length_mean": 606.3,
        "packet_length_std": 210.2,
        "syn_count": 2.0,
        "ack_count": 10.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.2,
    }


def test_valid_r10_dict_passes(valid_r10_dict):
    validator = FeatureSchemaValidator("R10")
    res = validator.validate(valid_r10_dict)
    assert res.is_valid
    assert res.contract == "R10"
    assert res.feature_names == list(R10_FEATURES)
    assert res.feature_matrix.shape == (1, 10)
    assert res.dataframe.iloc[0]["flow_duration_ms"] == pytest.approx(1200.5)


def test_missing_column_raises_error(valid_r10_dict):
    del valid_r10_dict["syn_ack_ratio"]
    validator = FeatureSchemaValidator("R10")
    with pytest.raises(FeatureValidationError, match="Missing required contract features"):
        validator.validate(valid_r10_dict)


def test_nan_value_raises_error(valid_r10_dict):
    valid_r10_dict["flow_bytes_per_s"] = float("nan")
    validator = FeatureSchemaValidator("R10")
    with pytest.raises(FeatureValidationError, match="NaN"):
        validator.validate(valid_r10_dict)


def test_inf_value_raises_error(valid_r10_dict):
    valid_r10_dict["flow_packets_per_s"] = float("inf")
    validator = FeatureSchemaValidator("R10")
    with pytest.raises(FeatureValidationError, match="infinite"):
        validator.validate(valid_r10_dict)


def test_metadata_stripped_from_feature_vector(valid_r10_dict):
    valid_r10_dict["src_ip"] = "192.168.1.50"
    valid_r10_dict["dst_ip"] = "10.0.0.1"
    valid_r10_dict["timestamp"] = 1700000000.0
    valid_r10_dict["label"] = "ATTACK"

    validator = FeatureSchemaValidator("R10")
    res = validator.validate(valid_r10_dict)
    assert res.is_valid
    assert res.feature_matrix.shape == (1, 10)
    assert "src_ip" not in res.dataframe.columns
    assert "timestamp" not in res.dataframe.columns
    assert res.dropped_metadata["src_ip"] == "192.168.1.50"
    assert res.dropped_metadata["label"] == "ATTACK"


def test_r4_contract_validation():
    r4_dict = {
        "flow_duration_ms": 500.0,
        "flow_packets_per_s": 10.0,
        "flow_bytes_per_s": 5000.0,
        "packet_length_mean": 500.0,
    }
    validator = FeatureSchemaValidator("R4")
    res = validator.validate(r4_dict)
    assert res.is_valid
    assert res.contract == "R4"
    assert res.feature_matrix.shape == (1, 4)
    assert res.feature_names == list(R4_FEATURES)
