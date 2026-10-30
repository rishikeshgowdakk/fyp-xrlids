"""Unit & Integration Tests for Multiclass Classification and Response Executor (Priority 4 & 5)."""

from __future__ import annotations

import tempfile
from pathlib import Path
import numpy as np
import pytest

from xrlids.features.definitions import R10_FEATURES
from xrlids.models.multiclass_detector import MulticlassAttackClassifier, MulticlassPrediction
from xrlids.response.executor import ActionLifecycleState, ResponseExecutor
from xrlids.response.feedback import ResponseOutcomeFeedbackLoop
from xrlids.response.safety import Action, DeterministicSafetyGate
from xrlids.response.transaction import SimulatedActuatorBackend
from xrlids.response.verification import ResponseVerifier, VerificationStatus


def test_multiclass_classifier_train_and_predict():
    """Verify multiclass training, calibrated inference, and UNKNOWN fallback."""
    rng = np.random.RandomState(42)
    X = rng.randn(60, 10).astype(np.float32)
    # 3 classes: BENIGN, DoS, DDoS
    y = np.array(["BENIGN"] * 20 + ["DoS"] * 20 + ["DDoS"] * 20)

    clf = MulticlassAttackClassifier(feature_names=R10_FEATURES, confidence_threshold=0.40)
    clf.fit(X, y)

    # Test single flow inference
    pred = clf.predict_family(X[0])
    assert isinstance(pred, MulticlassPrediction)
    assert pred.predicted_family in ("BENIGN", "DoS", "DDoS", "UNKNOWN")
    assert 0.0 <= pred.confidence <= 1.0
    assert len(pred.family_probabilities) == 3

    # Test batch prediction
    batch_preds = clf.predict_batch(X[:5])
    assert len(batch_preds) == 5
    for bp in batch_preds:
        assert isinstance(bp, MulticlassPrediction)

    # Test UNKNOWN fallback with impossibly high confidence threshold
    pred_unknown = clf.predict_family(X[0], confidence_threshold=0.9999)
    assert pred_unknown.predicted_family == "UNKNOWN"
    assert not pred_unknown.is_known_family


def test_multiclass_classifier_serialization():
    """Verify save and load roundtrip."""
    rng = np.random.RandomState(42)
    X = rng.randn(30, 10).astype(np.float32)
    y = np.array(["BENIGN"] * 15 + ["PortScan"] * 15)

    clf = MulticlassAttackClassifier()
    clf.fit(X, y)

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "test_mc.joblib"
        clf.save(p)
        assert p.is_file()

        loaded = MulticlassAttackClassifier.load(p)
        assert loaded.classes == clf.classes
        pred = loaded.predict_family(X[0])
        assert pred.predicted_family in ("BENIGN", "PortScan", "UNKNOWN")


def test_response_verifier_critical_host_immunity():
    """Verify that ResponseVerifier rejects disruptive actions on critical hosts."""
    verifier = ResponseVerifier(critical_hosts=["192.168.10.1", "gateway"])

    # Attempt to isolate critical gateway
    res = verifier.verify_action(
        action=Action.ISOLATE,
        target_host="192.168.10.1",
        is_advisory=False,
    )
    assert not res.verified
    assert res.status == VerificationStatus.FAILED_CRITICAL_HOST_IMPACTED
    assert res.collateral_disruption_detected


def test_response_verifier_advisory_mode():
    """Verify that advisory mode skips physical actuator verification cleanly."""
    verifier = ResponseVerifier()
    res = verifier.verify_action(
        action=Action.ISOLATE,
        target_host="10.0.0.99",
        is_advisory=True,
    )
    assert res.verified
    assert res.status == VerificationStatus.SKIPPED_ADVISORY


def test_response_outcome_feedback_loop():
    """Verify causal transition logging and reward calculations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "transitions.jsonl"
        loop = ResponseOutcomeFeedbackLoop(log_path=log_file, persist_to_disk=True)

        s_before = np.array([0.9, 0.2, 0.8, 0.0, 0.0, 0.5])
        s_after = np.array([0.1, -0.6, 0.2, 3.0, 1.0, 0.1])

        tr = loop.record_transition(
            target_host="192.168.1.100",
            state_before=s_before,
            action=Action.ISOLATE,
            state_after=s_after,
            verified=True,
            ground_truth=1,  # Ground truth attack
        )
        assert tr.reward > 0.0
        assert tr.action_taken == "ISOLATE"
        assert log_file.is_file()
        assert len(log_file.read_text().strip().split("\n")) == 1

        stats = loop.get_stats()
        assert stats["total_transitions"] == 1
        assert stats["cumulative_reward"] == round(tr.reward, 4)


def test_response_executor_lifecycle():
    """Verify the 5-stage action lifecycle through ResponseExecutor."""
    safety_gate = DeterministicSafetyGate(advisory_mode=True)
    executor = ResponseExecutor(safety_gate=safety_gate, advisory_mode=True, default_ttl_seconds=10.0)

    s_before = [0.85, 0.3, 0.7, 0.0, 0.0, 0.6]

    # 1. Normal threat execution (advisory)
    rep = executor.execute_action(
        proposed_action=Action.ISOLATE,
        target_host="192.168.1.200",
        state_before=s_before,
    )
    assert rep.final_lifecycle_state == ActionLifecycleState.VERIFIED
    assert rep.authorized_action == Action.ISOLATE
    assert rep.verification.verified
    assert "192.168.1.200" in executor.active_mitigations

    # 2. Critical host exemption rejection
    rep_crit = executor.execute_action(
        proposed_action=Action.ISOLATE,
        target_host="192.168.10.1",  # Critical default gateway
        state_before=s_before,
    )
    # Safety gate clamps ISOLATE on critical host to ALERT
    assert rep_crit.authorized_action == Action.ALERT
    assert rep_crit.final_lifecycle_state == ActionLifecycleState.REJECTED

    # 3. Expiration / Rollback test
    now = executor.active_mitigations["192.168.1.200"]["expire_timestamp"] + 1.0
    expired = executor.check_expirations(current_time=now)
    assert "192.168.1.200" in expired
    assert "192.168.1.200" not in executor.active_mitigations
