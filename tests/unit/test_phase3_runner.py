"""Unit tests for Phase 3 LivePipelineRunner and safety invariants."""

import pytest
import numpy as np

from xrlids.demo.pcap import PacketInfo
from xrlids.live.capture import PacketCaptureService
from xrlids.live.flow_builder import LiveFlowBuilder
from xrlids.live.runner import LiveMode, LivePipelineRunner
from xrlids.response.baselines import SingleThresholdPolicy
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action


class MockDetector:
    def __init__(self, score: float = 0.90, should_raise: bool = False):
        self.score = score
        self.should_raise = should_raise

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.should_raise:
            raise RuntimeError("Simulated detector hardware failure")
        return np.array([[1.0 - self.score, self.score]])


class FailingPolicy:
    def predict_action(self, *args, **kwargs):
        raise RuntimeError("Simulated policy inference crash")


def test_dry_run_pipeline_execution():
    """Verify dry-run mode processes packets, evaluates policy, and records audit cards with 0 mutations."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0, "192.168.1.10", "10.0.0.1", 5000, 80, 6, 64, is_tcp=True, syn=True),
        PacketInfo(t0 + 0.01, "10.0.0.1", "192.168.1.10", 80, 5000, 6, 64, is_tcp=True, rst=True),
    ]

    capture = PacketCaptureService(synthetic_stream=packets)
    detector = MockDetector(score=0.85)
    policy = SingleThresholdPolicy(threshold=0.50)
    safety_gate = DeterministicSafetyGate()

    runner = LivePipelineRunner(
        capture_service=capture,
        detector_model=detector,
        policy=policy,
        safety_gate=safety_gate,
        mode=LiveMode.DRY_RUN,
    )

    report = runner.run()

    assert report["zero_network_mutation_guaranteed"] is True
    assert report["flows_processed"] == 1
    assert len(runner.auditor.audit_cards) == 1

    card = runner.auditor.audit_cards[0]
    assert card.threat_score == 0.85
    assert card.proposed_action == "ISOLATE"
    assert card.enforced_action == "ISOLATE"
    assert card.safety_override is False
    assert len(card.r10_features) == 10


def test_safety_gate_critical_host_override():
    """Verify safety gate downgrades ISOLATE to ALERT for critical infrastructure hosts."""
    t0 = 1700000000.0
    # Host 192.168.10.1 is in DEFAULT_CRITICAL_HOSTS
    packets = [
        PacketInfo(t0, "192.168.10.1", "10.0.0.1", 5000, 80, 6, 64, is_tcp=True, syn=True),
        PacketInfo(t0 + 0.01, "10.0.0.1", "192.168.10.1", 80, 5000, 6, 64, is_tcp=True, rst=True),
    ]

    capture = PacketCaptureService(synthetic_stream=packets)
    detector = MockDetector(score=0.90)
    policy = SingleThresholdPolicy(threshold=0.50)
    safety_gate = DeterministicSafetyGate()

    runner = LivePipelineRunner(
        capture_service=capture,
        detector_model=detector,
        policy=policy,
        safety_gate=safety_gate,
        mode=LiveMode.DRY_RUN,
    )

    report = runner.run()
    assert report["flows_processed"] == 1
    card = runner.auditor.audit_cards[0]
    assert card.proposed_action == "ISOLATE"
    assert card.enforced_action == "ALERT"
    assert card.safety_override is True
    assert "critical_infrastructure" in card.override_reason.lower()



def test_observe_mode_passive_execution():
    """Verify observe mode evaluates threat scores but executes no response policies."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0, "192.168.1.10", "10.0.0.1", 5000, 80, 6, 64, is_tcp=True, rst=True),
    ]

    capture = PacketCaptureService(synthetic_stream=packets)
    detector = MockDetector(score=0.95)
    policy = SingleThresholdPolicy(threshold=0.50)

    runner = LivePipelineRunner(
        capture_service=capture,
        detector_model=detector,
        policy=policy,
        mode=LiveMode.OBSERVE,
    )

    report = runner.run()

    assert report["flows_processed"] == 1
    # In OBSERVE mode, no response audit cards are recorded
    assert len(runner.auditor.audit_cards) == 0


def test_controlled_enforcement_mode_strictly_locked():
    """Verify attempting to initialize controlled enforcement raises RuntimeError."""
    capture = PacketCaptureService(synthetic_stream=[])
    with pytest.raises(RuntimeError, match="Controlled enforcement mode is locked"):
        LivePipelineRunner(capture_service=capture, mode=LiveMode.CONTROLLED_ENFORCEMENT)


def test_failsafe_invariant_detector_crash():
    """Verify pipeline continues and fails safe to ALLOW when detector raises exception."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0, "192.168.1.10", "10.0.0.1", 5000, 80, 6, 64, is_tcp=True, rst=True),
    ]

    capture = PacketCaptureService(synthetic_stream=packets)
    failing_detector = MockDetector(should_raise=True)
    policy = SingleThresholdPolicy(threshold=0.50)

    runner = LivePipelineRunner(
        capture_service=capture,
        detector_model=failing_detector,
        policy=policy,
        mode=LiveMode.DRY_RUN,
    )

    report = runner.run()
    assert report["flows_processed"] == 1
    assert runner.auditor.inference_failures >= 1
    assert len(runner.auditor.audit_cards) == 1
    # Fallback threat score 0.0 results in ALLOW
    assert runner.auditor.audit_cards[0].enforced_action == "ALLOW"


def test_failsafe_invariant_policy_crash():
    """Verify pipeline continues and defaults proposed action to ALLOW on policy failure."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0, "192.168.1.10", "10.0.0.1", 5000, 80, 6, 64, is_tcp=True, rst=True),
    ]

    capture = PacketCaptureService(synthetic_stream=packets)
    detector = MockDetector(score=0.99)
    failing_policy = FailingPolicy()

    runner = LivePipelineRunner(
        capture_service=capture,
        detector_model=detector,
        policy=failing_policy,
        mode=LiveMode.DRY_RUN,
    )

    report = runner.run()
    assert report["flows_processed"] == 1
    assert runner.auditor.inference_failures >= 1
    assert runner.auditor.audit_cards[0].proposed_action == "ALLOW"
    assert runner.auditor.audit_cards[0].enforced_action == "ALLOW"
