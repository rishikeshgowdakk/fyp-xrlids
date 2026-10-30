"""Unit tests for UnifiedInferenceService and SequenceBufferManager."""

from __future__ import annotations

import pytest

from xrlids.features.definitions import R10_FEATURES
from xrlids.models.inference_service import SequenceBufferManager, UnifiedInferenceService


@pytest.fixture
def sample_r10_features():
    return {
        "flow_duration_ms": 1250.0,
        "flow_packets_per_s": 150.0,
        "flow_bytes_per_s": 85000.0,
        "packet_length_mean": 566.6,
        "packet_length_std": 240.2,
        "syn_count": 1.0,
        "ack_count": 1.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 1.0,
    }


def test_sequence_buffer_manager():
    """Verify SequenceBufferManager isolates sessions and returns sequence only at T=5."""
    mgr = SequenceBufferManager(seq_len=5)
    key_a = "192.168.1.10:80"
    key_b = "192.168.1.20:443"

    import numpy as np

    v1 = np.ones(10, dtype=np.float32)

    # First 4 flows for session A
    for i in range(4):
        seq, count = mgr.add_flow_vector(key_a, v1 * (i + 1))
        assert seq is None
        assert count == i + 1

    # Session B flow does not interfere with A
    seq_b, count_b = mgr.add_flow_vector(key_b, v1)
    assert seq_b is None
    assert count_b == 1

    # 5th flow for session A triggers sequence creation
    seq_a, count_a = mgr.add_flow_vector(key_a, v1 * 5)
    assert seq_a is not None
    assert count_a == 5
    assert seq_a.shape == (1, 5, 10)


def test_unified_inference_service_rf_only(sample_r10_features):
    """Verify single-flow inference produces RF output when sequence is incomplete."""
    service = UnifiedInferenceService()
    res = service.infer(
        features=sample_r10_features,
        session_key="single_flow_session",
        benchmark="cicids2017",
    )
    assert res.inference_source == "RANDOM_FOREST"
    assert res.rf_score >= 0.0
    assert res.lstm_score is None
    assert res.fusion_score is None
    assert res.sequence_length_available == 1
    assert res.latency_ms > 0.0


def test_unified_inference_service_progression_to_fusion(sample_r10_features):
    """Verify streaming 5 flows on one session key transitions from RF to RF+LSTM Fusion."""
    service = UnifiedInferenceService()
    sess = "continuous_session_1"

    results = []
    for _ in range(5):
        res = service.infer(
            features=sample_r10_features,
            session_key=sess,
            benchmark="cicids2017",
        )
        results.append(res)

    # Flows 1..4 are RF only
    for r in results[:4]:
        assert r.inference_source == "RANDOM_FOREST"
        assert r.lstm_score is None

    # Flow 5 has complete sequence and uses Fusion
    r5 = results[4]
    assert r5.sequence_length_available == 5
    assert r5.inference_source == "RF+LSTM_FUSION"
    assert r5.lstm_score is not None
    assert r5.fusion_score is not None
    # Verify fusion formula: S = 0.5 * rf + 0.5 * lstm
    expected_fusion = 0.5 * r5.rf_score + 0.5 * r5.lstm_score
    assert abs(r5.fusion_score - expected_fusion) < 1e-3


def test_unified_inference_feature_validation(sample_r10_features):
    """Verify validation rejects missing features and non-numeric inputs."""
    service = UnifiedInferenceService()

    bad_features = dict(sample_r10_features)
    del bad_features["syn_count"]
    with pytest.raises(ValueError, match="Missing required features"):
        service.infer(bad_features, session_key="s1")

    bad_val = dict(sample_r10_features)
    bad_val["syn_count"] = float("nan")
    with pytest.raises(ValueError, match="invalid value"):
        service.infer(bad_val, session_key="s2")
