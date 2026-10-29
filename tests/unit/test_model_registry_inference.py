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
from unittest.mock import patch
import numpy as np
import pytest

from xrlids.demo.replay import NoDetectorLoadedError, ReplayEngine
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES
from xrlids.models.registry import (
    DEFAULT_MODEL_REGISTRY,
    InferenceResult,
    ModelMetadata,
    ModelRegistry,
    ModelRegistryError,
    ValidationError,
)

import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


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


# ---------------------------------------------------------------------------
# 5. Contract Enforcement Across All Three Benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("benchmark,contract,valid_dict", [
    ("cicids2017", "R10", _valid_r10_dict()),
    ("cse2018", "R10", _valid_r10_dict()),
    ("unswnb15", "R4", _valid_r4_dict()),
])
def test_contract_enforcement_all_benchmarks(benchmark: str, contract: str, valid_dict: dict[str, float]):
    registry = DEFAULT_MODEL_REGISTRY
    meta = registry.get_metadata(benchmark)
    assert meta.feature_contract == contract

    # Valid dictionary succeeds
    result = registry.infer(valid_dict, benchmark=benchmark)
    assert result.benchmark == benchmark
    assert result.feature_contract == contract
    assert len(result.features_validated) == len(meta.expected_features)

    # Missing a feature raises ValidationError
    incomplete = dict(valid_dict)
    key_to_remove = next(iter(incomplete.keys()))
    del incomplete[key_to_remove]
    with pytest.raises(ValidationError, match="missing required features"):
        registry.infer(incomplete, benchmark=benchmark)


def test_r10_benchmarks_reject_r4_inputs():
    registry = DEFAULT_MODEL_REGISTRY
    r4_input = _valid_r4_dict()
    for bench in ("cicids2017", "cse2018"):
        with pytest.raises(ValidationError, match="missing required features"):
            registry.infer(r4_input, benchmark=bench)


def test_unsw_r4_accepts_minimal_features_without_r10_extras():
    registry = DEFAULT_MODEL_REGISTRY
    r4_input = _valid_r4_dict()
    # UNSW R4 must NOT require TCP flags or packet_length_std
    result = registry.infer(r4_input, benchmark="unswnb15")
    assert result.feature_contract == "R4"
    assert "packet_length_std" not in result.features_validated
    assert "syn_count" not in result.features_validated


def test_model_preprocessor_compatibility_validation_all_benchmarks():
    registry = DEFAULT_MODEL_REGISTRY
    for bench in ("cicids2017", "cse2018", "unswnb15"):
        report = registry.validate_model_preprocessor_compatibility(bench)
        assert isinstance(report, dict)
        assert report["benchmark"] == bench
        assert report["feature_count"] == len(registry.get_metadata(bench).expected_features)


# ---------------------------------------------------------------------------
# 6. Explicit Rejection of Model / Preprocessor Schema Mismatch
# ---------------------------------------------------------------------------

def test_schema_mismatch_rejected_explicitly():
    """Verify that if preprocessor output columns do not match model features, ModelRegistryError is raised."""
    registry = DEFAULT_MODEL_REGISTRY
    meta_17 = registry.get_metadata("cicids2017")
    meta_unsw = registry.get_metadata("unswnb15")

    # Construct an artificial mismatched metadata entry: R10 model with R4 preprocessor
    mismatched_meta = ModelMetadata(
        model_id="test_mismatch",
        benchmark="mismatched",
        feature_contract="R10",
        expected_features=list(R10_FEATURES),
        model_path=meta_17.model_path,
        preprocessor_path=meta_unsw.preprocessor_path,  # R4 preprocessor has 4 features, model has 10
        model_type="rf",
    )
    test_reg = ModelRegistry(repo_root=REPO_ROOT)
    test_reg.register(mismatched_meta)

    with pytest.raises(ModelRegistryError, match="Model/preprocessor schema mismatch"):
        test_reg.infer(_valid_r10_dict(), benchmark="mismatched")

    with pytest.raises(ModelRegistryError, match="Schema mismatch for benchmark"):
        test_reg.validate_model_preprocessor_compatibility("mismatched")


# ---------------------------------------------------------------------------
# 7. Comprehensive Rejection of Invalid Numeric & Non-numeric Values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_val", [
    float("nan"),
    float("inf"),
    float("-inf"),
    "malicious_string",
    None,
    [123],
    {"nested": 1},
])
def test_all_benchmarks_reject_invalid_feature_values(bad_val):
    registry = DEFAULT_MODEL_REGISTRY
    for bench, valid_dict in (("cicids2017", _valid_r10_dict()), ("unswnb15", _valid_r4_dict())):
        features = dict(valid_dict)
        first_key = next(iter(features.keys()))
        features[first_key] = bad_val
        with pytest.raises(ValidationError):
            registry.infer(features, benchmark=bench)


# ---------------------------------------------------------------------------
# 8. Class-to-Probability Mapping Verification Across All Benchmarks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("benchmark,sample_input", [
    ("cicids2017", _valid_r10_dict()),
    ("cse2018", _valid_r10_dict()),
    ("unswnb15", _valid_r4_dict()),
])
def test_class_to_probability_mapping_exact(benchmark: str, sample_input: dict[str, float]):
    registry = DEFAULT_MODEL_REGISTRY
    result = registry.infer(sample_input, benchmark=benchmark, threshold=0.50)

    # 1. Classes and mapping
    assert set(result.raw_probabilities.keys()) == {"BENIGN", "ATTACK"}
    benign_prob = result.raw_probabilities["BENIGN"]
    attack_prob = result.raw_probabilities["ATTACK"]

    # 2. Probability sum invariant
    assert abs((benign_prob + attack_prob) - 1.0) < 1e-4

    # 3. Attack score alignment
    assert abs(result.attack_score - attack_prob) < 1e-4

    # 4. Threshold rule invariant
    if result.attack_score >= 0.50:
        assert result.prediction == 1
        assert result.prediction_label == "ATTACK"
    else:
        assert result.prediction == 0
        assert result.prediction_label == "BENIGN"


# ---------------------------------------------------------------------------
# 9. TreeSHAP Attribution and Missing Explanation Features
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("benchmark,sample_input,expected_count", [
    ("cicids2017", _valid_r10_dict(), 10),
    ("cse2018", _valid_r10_dict(), 10),
    ("unswnb15", {f: 120.0 for f in R4_FEATURES}, 4),
])
def test_treeshap_returns_real_attributions(benchmark: str, sample_input: dict[str, float], expected_count: int):
    explanation = explain_flow_prediction(sample_input, benchmark=benchmark)
    assert len(explanation["features"]) == expected_count
    assert len(explanation["attributions"]) == expected_count
    assert isinstance(explanation["base_value"], float)
    assert math.isfinite(explanation["base_value"])

    for item in explanation["features"]:
        assert math.isfinite(item["shap_attribution"])
        assert item["direction"] in ("INCREASES_THREAT", "DECREASES_THREAT")
        assert math.isfinite(item["value"])

    # Verify not all attributions are zero
    attrs = [item["shap_attribution"] for item in explanation["features"]]
    assert any(a != 0.0 for a in attrs), f"Expected real non-zero attributions for {benchmark}"


def test_missing_explanation_features_produce_clear_error_state():
    # Empty features
    with pytest.raises(ValueError, match="missing required features"):
        explain_flow_prediction({}, benchmark="cicids2017")

    # Incomplete features
    with pytest.raises(ValueError, match="missing required features"):
        explain_flow_prediction({"flow_duration_ms": 100.0}, benchmark="cse2018")

    # Non-dictionary
    with pytest.raises(ValueError, match="must be a dictionary"):
        explain_flow_prediction(["invalid"], benchmark="unswnb15")  # type: ignore


# ---------------------------------------------------------------------------
# 10. Distinct Runtime Modes (Live, PCAP, Dataset Replay, Sample)
# ---------------------------------------------------------------------------

def test_distinguishable_runtime_modes(tmp_path: Path):
    from dashboard.server import LiveSession
    from xrlids.demo.pcap import write_pcap, build_raw_packet
    from xrlids.demo.replay import ReplayEngine

    # Dummy pcap for test
    pcap = tmp_path / "mode_test.pcap"
    packets = [(100.0, build_raw_packet("10.0.0.1", "10.0.0.2", 1234, 80, 6, payload_len=20))]
    write_pcap(pcap, packets)

    class _DummyModel:
        def predict_proba(self, X):
            return np.array([[0.5, 0.5]] * len(X))

    engine = ReplayEngine(model=_DummyModel(), threshold=0.50)
    session = LiveSession(engine=engine)

    # 1. Sample mode
    res_sample = session.start(mode="sample", pcap=str(pcap), pace_speed=1000.0, loop=False)
    assert res_sample["mode"] == "sample"
    assert res_sample["is_simulated"] is True
    session.stop()

    # 2. Dataset mode
    res_dataset = session.start(mode="dataset", dataset_category="benign", pace_speed=1000.0, loop=False)
    assert res_dataset["mode"] == "dataset"
    assert res_dataset.get("dataset_category") == "benign"
    session.stop()

    # 3. PCAP mode
    res_pcap = session.start(mode="pcap", pcap=str(pcap), pace_speed=1000.0, loop=False)
    assert res_pcap["mode"] == "pcap"
    assert res_pcap["is_simulated"] is False
    session.stop()


# ---------------------------------------------------------------------------
# 11. DQN Recommendations Remain Advisory / Dry-Run (Zero Firewall Mutations)
# ---------------------------------------------------------------------------

def test_dqn_recommendations_remain_advisory_zero_firewall_mutations():
    """Verify that DQN action inference produces advisory recommendations with zero host firewall mutations."""
    from xrlids.response.types import Action, ActionSpaceMode
    from xrlids.response.dqn.agent import DqnAgent
    from xrlids.response.dqn.policy import DqnPolicy

    agent = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.FOUR_ACTION, hidden_dim=32)

    # State: [attack_score, flow_bytes_per_s, flow_packets_per_s, duration_ms, host_prior_cost, anomaly_score]
    dummy_state = np.array([0.95, 15000.0, 120.0, 3000.0, 0.0, 0.8], dtype=np.float32)

    # Patch subprocess to guarantee no system firewall mutation command (iptables/nftables) is called
    with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen, patch("os.system") as mock_os:
        action, q_vals, margin = agent.select_action(dummy_state, epsilon=0.0)

        # Assert valid action recommendation
        assert action in (Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE)
        assert len(q_vals) == 4
        assert margin >= 0.0

        # Assert zero system calls for network mutations
        mock_run.assert_not_called()
        mock_popen.assert_not_called()
        mock_os.assert_not_called()

