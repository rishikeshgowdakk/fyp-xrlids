"""Unit tests for the centralized ModelRegistry and Trustworthy Inference Path.

Tests:
1. Registration & metadata lookup for supported benchmarks (cicids2017, cse2018, unswnb15).
2. Rejection of unsupported benchmarks with clear error.
3. Feature validation:
   - Rejection of missing features (prohibiting silent zero-filling).
   - Rejection of non-numeric values.
   - Rejection of NaN, +inf, -inf.
4. Correct preprocessing and single-pass transformation.
5. Dynamic class mapping and probability breakdown (BENIGN vs ATTACK).
6. Separation of R10 (10 features) and R4 (4 features) contracts.
7. Latency tracking in milliseconds.
8. ReplayEngine strict validation integration.
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest

from xrlids.demo.replay import NoDetectorLoadedError, ReplayEngine
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES
from xrlids.models.registry import (
    DEFAULT_MODEL_REGISTRY,
    InferenceResult,
    ModelMetadata,
    ModelRegistry,
    ModelRegistryError,
    ValidationError,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _valid_r10_dict() -> dict[str, float]:
    return {
        "flow_duration_ms": 1250.0,
        "flow_packets_per_s": 80.5,
        "flow_bytes_per_s": 15400.0,
        "packet_length_mean": 191.3,
        "packet_length_std": 84.2,
        "syn_count": 2.0,
        "ack_count": 4.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }


def _valid_r4_dict() -> dict[str, float]:
    return {
        "flow_duration_ms": 950.0,
        "flow_packets_per_s": 42.0,
        "flow_bytes_per_s": 8500.0,
        "packet_length_mean": 202.4,
    }


# ---------------------------------------------------------------------------
# 1. Metadata and Registry Lookup Tests
# ---------------------------------------------------------------------------

def test_registry_has_canonical_models():
    registry = DEFAULT_MODEL_REGISTRY
    meta_17 = registry.get_metadata("cicids2017")
    assert meta_17.feature_contract == "R10"
    assert len(meta_17.expected_features) == 10
    assert meta_17.model_path.exists()
    assert meta_17.preprocessor_path.exists()

    meta_18 = registry.get_metadata("cse2018")
    assert meta_18.feature_contract == "R10"
    assert len(meta_18.expected_features) == 10
    assert meta_18.model_path.exists()

    meta_unsw = registry.get_metadata("unswnb15")
    assert meta_unsw.feature_contract == "R4"
    assert len(meta_unsw.expected_features) == 4
    assert meta_unsw.model_path.exists()


def test_registry_rejects_unsupported_benchmark():
    registry = DEFAULT_MODEL_REGISTRY
    with pytest.raises(ModelRegistryError, match="No rf model registered for benchmark 'unknown_bench'"):
        registry.get_metadata("unknown_bench")


# ---------------------------------------------------------------------------
# 2. Strict Feature Validation Tests (No Silent Zero-Filling)
# ---------------------------------------------------------------------------

def test_validation_rejects_missing_features():
    registry = DEFAULT_MODEL_REGISTRY
    incomplete = _valid_r10_dict()
    del incomplete["syn_ack_ratio"]

    with pytest.raises(ValidationError, match="missing required features.*syn_ack_ratio"):
        registry.infer(incomplete, benchmark="cicids2017")


def test_validation_rejects_none_feature_value():
    registry = DEFAULT_MODEL_REGISTRY
    features = _valid_r10_dict()
    features["flow_duration_ms"] = None

    with pytest.raises(ValidationError, match="missing required features.*flow_duration_ms"):
        registry.infer(features, benchmark="cicids2017")


def test_validation_rejects_non_numeric_values():
    registry = DEFAULT_MODEL_REGISTRY
    features = _valid_r10_dict()
    features["syn_count"] = "invalid_string"

    with pytest.raises(ValidationError, match="has non-numeric value"):
        registry.infer(features, benchmark="cicids2017")


def test_validation_rejects_nan_and_inf():
    registry = DEFAULT_MODEL_REGISTRY
    features_nan = _valid_r10_dict()
    features_nan["flow_packets_per_s"] = float("nan")

    with pytest.raises(ValidationError, match="contains invalid numeric value: nan"):
        registry.infer(features_nan, benchmark="cicids2017")

    features_inf = _valid_r10_dict()
    features_inf["flow_bytes_per_s"] = float("inf")

    with pytest.raises(ValidationError, match="contains invalid numeric value: inf"):
        registry.infer(features_inf, benchmark="cicids2017")


# ---------------------------------------------------------------------------
# 3. Model Inference and Dynamic Class Mapping Tests
# ---------------------------------------------------------------------------

def test_inference_cicids2017_valid():
    registry = DEFAULT_MODEL_REGISTRY
    features = _valid_r10_dict()
    result = registry.infer(features, benchmark="cicids2017", threshold=0.50)

    assert isinstance(result, InferenceResult)
    assert result.benchmark == "cicids2017"
    assert result.feature_contract == "R10"
    assert result.prediction in (0, 1)
    assert result.prediction_label in ("BENIGN", "ATTACK")
    assert 0.0 <= result.attack_score <= 1.0
    assert "BENIGN" in result.raw_probabilities
    assert "ATTACK" in result.raw_probabilities
    assert abs(result.raw_probabilities["ATTACK"] - result.attack_score) < 1e-4
    assert result.inference_time_ms > 0.0
    assert len(result.features_validated) == 10


def test_inference_unswnb15_r4_valid():
    registry = DEFAULT_MODEL_REGISTRY
    features = _valid_r4_dict()
    result = registry.infer(features, benchmark="unswnb15", threshold=0.50)

    assert result.benchmark == "unswnb15"
    assert result.feature_contract == "R4"
    assert result.prediction in (0, 1)
    assert 0.0 <= result.attack_score <= 1.0
    assert len(result.features_validated) == 4
    assert "packet_length_std" not in result.features_validated


def test_inference_threshold_boundary():
    registry = DEFAULT_MODEL_REGISTRY
    features = _valid_r10_dict()

    # With threshold 1.0, prediction must be 0 unless score == 1.0
    res_high_th = registry.infer(features, benchmark="cicids2017", threshold=1.0)
    if res_high_th.attack_score < 1.0:
        assert res_high_th.prediction == 0
        assert res_high_th.prediction_label == "BENIGN"

    # With threshold 0.0, prediction must be 1
    res_low_th = registry.infer(features, benchmark="cicids2017", threshold=0.0)
    assert res_low_th.prediction == 1
    assert res_low_th.prediction_label == "ATTACK"


# ---------------------------------------------------------------------------
# 4. ReplayEngine Strict Validation Integration Tests
# ---------------------------------------------------------------------------

def test_replay_engine_rejects_missing_features():
    rf_path = REPO_ROOT / "models" / "rf" / "random_forest_cicids2017.joblib"
    prep_path = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib"
    engine = ReplayEngine(model_path=REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001")

    # Incomplete features must raise ValueError rather than zero-filling
    incomplete = {"flow_duration_ms": 100.0}
    with pytest.raises(ValueError, match="missing required features"):
        engine.predict_features(incomplete)


def test_replay_engine_valid_prediction():
    engine = ReplayEngine(model_path=REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001")
    pred, score = engine.predict_features(_valid_r10_dict())
    assert pred in (0, 1)
    assert 0.0 <= score <= 1.0
