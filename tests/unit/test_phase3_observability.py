"""Unit tests for Phase 3F Observability, Health Monitoring, and Failure Injection."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from xrlids.demo.flow import Flow, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.live import (
    BackpressureDropEvent,
    BoundedFlowQueue,
    CaptureConfig,
    FailureInjectionHarness,
    HealthConfig,
    HealthMonitor,
    HealthReport,
    HealthState,
    LiveMode,
    LivePipelineRunner,
    PacketCaptureService,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.types import Action


def _make_dummy_packet(src_ip: str = "192.168.1.10", dst_ip: str = "10.0.0.1", seq: int = 1) -> PacketInfo:
    return PacketInfo(
        timestamp=1700000000.0 + seq * 0.01,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000 + seq,
        dst_port=80,
        protocol=6,
        packet_length=64,
        is_tcp=True,
        syn=(seq == 1),
        fin=(seq > 1),
        ack=True,
    )


def test_health_monitor_healthy_state():
    """Verify nominal queue and error metrics produce HEALTHY state."""
    monitor = HealthMonitor()
    queue_stats = {"current_depth": 10, "capacity": 100, "overflow_count": 0}
    error_counts = {"detector_failures": 0, "policy_failures": 0, "safety_gate_failures": 0, "audit_write_failures": 0}

    report = monitor.evaluate(queue_stats, error_counts)
    assert report.state == HealthState.HEALTHY
    assert "nominal" in report.reasons[0].lower()


def test_health_monitor_degraded_state():
    """Verify queue saturation or backpressure drops trigger DEGRADED state."""
    monitor = HealthMonitor(HealthConfig(degraded_queue_fill_pct=80.0, degraded_backpressure_drops_threshold=1))

    # High fill percentage
    queue_stats_full = {"current_depth": 85, "capacity": 100, "overflow_count": 0}
    error_counts = {"detector_failures": 0, "policy_failures": 0, "safety_gate_failures": 0, "audit_write_failures": 0}
    report = monitor.evaluate(queue_stats_full, error_counts)
    assert report.state == HealthState.DEGRADED
    assert any("Queue capacity fill" in r for r in report.reasons)

    # Backpressure drops
    queue_stats_drops = {"current_depth": 20, "capacity": 100, "overflow_count": 2}
    report2 = monitor.evaluate(queue_stats_drops, error_counts)
    assert report2.state == HealthState.DEGRADED
    assert any("Backpressure drops" in r for r in report2.reasons)


def test_health_monitor_failed_safe_state():
    """Verify critical subsystem errors trigger FAILED_SAFE state immediately."""
    monitor = HealthMonitor()
    queue_stats = {"current_depth": 0, "capacity": 100, "overflow_count": 0}

    # Detector failure
    errs = {"detector_failures": 1, "policy_failures": 0, "safety_gate_failures": 0, "audit_write_failures": 0}
    rep = monitor.evaluate(queue_stats, errs)
    assert rep.state == HealthState.FAILED_SAFE
    assert any("Detector" in r for r in rep.reasons)

    # Policy failure
    errs2 = {"detector_failures": 0, "policy_failures": 1, "safety_gate_failures": 0, "audit_write_failures": 0}
    rep2 = monitor.evaluate(queue_stats, errs2)
    assert rep2.state == HealthState.FAILED_SAFE
    assert any("Policy" in r for r in rep2.reasons)

    # Safety gate failure
    errs3 = {"detector_failures": 0, "policy_failures": 0, "safety_gate_failures": 1, "audit_write_failures": 0}
    rep3 = monitor.evaluate(queue_stats, errs3)
    assert rep3.state == HealthState.FAILED_SAFE
    assert any("Safety gate" in r for r in rep3.reasons)

    # Audit write failure
    errs4 = {"detector_failures": 0, "policy_failures": 0, "safety_gate_failures": 0, "audit_write_failures": 1}
    rep4 = monitor.evaluate(queue_stats, errs4)
    assert rep4.state == HealthState.FAILED_SAFE
    assert any("Audit" in r for r in rep4.reasons)


def test_bounded_flow_queue_fifo_and_watermark():
    """Verify FIFO ordering, latency measurement, and high watermark tracking."""
    queue = BoundedFlowQueue(capacity=10)
    assert queue.is_empty()
    assert not queue.is_full()

    # Enqueue 5 flows
    for i in range(5):
        key = FlowKey(f"192.168.1.{i}", "10.0.0.1", 1000 + i, 80, 6)
        flow = Flow(key=key, start_time=1.0, last_time=2.0)
        assert queue.enqueue(flow, flow_id=i + 1)

    assert queue.current_depth == 5
    assert queue.high_watermark == 5
    assert queue.oldest_item_age_s >= 0.0

    # Dequeue 2 flows
    item1 = queue.dequeue()
    assert item1 is not None
    assert item1[2] == 1  # flow_id == 1 (FIFO)
    assert item1[1] >= 0.0  # wait_time_s

    item2 = queue.dequeue()
    assert item2 is not None
    assert item2[2] == 2  # flow_id == 2 (FIFO)

    assert queue.current_depth == 3
    assert queue.high_watermark == 5  # Watermark retained

    stats = queue.stats()
    assert stats["enqueue_count"] == 5
    assert stats["dequeue_count"] == 2
    assert stats["high_watermark"] == 5
    assert stats["queue_latency_us"]["count"] == 2


def test_bounded_flow_queue_saturation_and_backpressure_drops():
    """Verify queue saturation rejects excess items and records BackpressureDropEvent."""
    capacity = 3
    queue = BoundedFlowQueue(capacity=capacity)

    # Fill to capacity
    for i in range(capacity):
        key = FlowKey(f"10.0.0.{i}", "10.0.0.1", 1000 + i, 80, 6)
        flow = Flow(key=key, start_time=1.0, last_time=2.0)
        assert queue.enqueue(flow, flow_id=i + 1)

    assert queue.is_full()
    assert queue.current_depth == capacity

    # Overfill by 2 items
    for j in range(2):
        key = FlowKey(f"10.0.1.{j}", "10.0.0.1", 2000 + j, 80, 6)
        flow = Flow(key=key, start_time=1.0, last_time=2.0)
        assert not queue.enqueue(flow, flow_id=capacity + j + 1)

    stats = queue.stats()
    assert stats["overflow_count"] == 2
    assert stats["backpressure_drops"] == 2
    assert stats["drop_events_count"] == 2
    assert stats["high_watermark"] == capacity


def test_failure_injection_harness_queue_saturation():
    """Verify FailureInjectionHarness.test_queue_saturation runs cleanly."""
    res = FailureInjectionHarness.test_queue_saturation(queue_capacity=4, burst_flows_count=10)
    assert res["pass"] is True
    assert res["high_watermark"] == 4
    assert res["overflow_count"] == 6
    assert res["accepted_count"] == 4
    assert res["rejected_count"] == 6


def test_failure_injection_harness_detector_failure():
    """Verify detector failure triggers fail-safe ALLOW and health transition."""
    packets = [_make_dummy_packet(seq=1), _make_dummy_packet(seq=2)]
    cap = PacketCaptureService(synthetic_stream=packets)
    gate = DeterministicSafetyGate()
    runner = LivePipelineRunner(capture_service=cap, safety_gate=gate, mode=LiveMode.DRY_RUN)

    res = FailureInjectionHarness.test_detector_failure_failsafe(runner)
    assert res["pass"] is True
    assert res["crashed"] is False
    assert res["failure_recorded"] is True
    assert res["fallback_to_safe_action"] is True

    # Check health report after failure
    report = runner.get_report()
    assert report["health_report"]["state"] == HealthState.FAILED_SAFE.value


def test_failure_injection_harness_policy_failure():
    """Verify policy failure triggers fail-safe action and error recording."""
    packets = [_make_dummy_packet(seq=1), _make_dummy_packet(seq=2)]
    cap = PacketCaptureService(synthetic_stream=packets)
    gate = DeterministicSafetyGate()
    runner = LivePipelineRunner(capture_service=cap, safety_gate=gate, mode=LiveMode.DRY_RUN)

    res = FailureInjectionHarness.test_policy_failure_failsafe(runner)
    assert res["pass"] is True
    assert res["crashed"] is False
    assert res["failure_recorded"] is True
    assert res["fallback_to_safe_action"] is True

    report = runner.get_report()
    assert report["health_report"]["state"] == HealthState.FAILED_SAFE.value


def test_failure_injection_harness_safety_gate_failure():
    """Verify safety gate failure forces ALLOW fallback."""
    packets = [_make_dummy_packet(seq=1), _make_dummy_packet(seq=2)]
    cap = PacketCaptureService(synthetic_stream=packets)
    gate = DeterministicSafetyGate()
    runner = LivePipelineRunner(capture_service=cap, safety_gate=gate, mode=LiveMode.DRY_RUN)

    res = FailureInjectionHarness.test_safety_gate_failure_failsafe(runner)
    assert res["pass"] is True
    assert res["crashed"] is False
    assert res["fallback_to_allow"] is True

    report = runner.get_report()
    assert report["health_report"]["state"] == HealthState.FAILED_SAFE.value


def test_failure_injection_harness_audit_failure():
    """Verify audit write failure preserves zero network mutation and marks FAILED_SAFE."""
    packets = [_make_dummy_packet(seq=1), _make_dummy_packet(seq=2)]
    cap = PacketCaptureService(synthetic_stream=packets)
    gate = DeterministicSafetyGate()
    runner = LivePipelineRunner(capture_service=cap, safety_gate=gate, mode=LiveMode.DRY_RUN)

    res = FailureInjectionHarness.test_audit_persistence_failure_lock(runner)
    assert res["pass"] is True
    assert res["crashed"] is False
    assert res["zero_network_mutation_guaranteed"] is True

    report = runner.get_report()
    assert report["health_report"]["state"] == HealthState.FAILED_SAFE.value


def test_controlled_enforcement_lock():
    """Verify controlled enforcement remains unconditionally locked."""
    cap = PacketCaptureService(synthetic_stream=[_make_dummy_packet()])
    with pytest.raises(RuntimeError, match="Controlled enforcement mode is locked"):
        LivePipelineRunner(capture_service=cap, mode=LiveMode.CONTROLLED_ENFORCEMENT)


def test_full_observability_report_structure():
    """Verify comprehensive metrics telemetry in runner report."""
    packets = [_make_dummy_packet(seq=1), _make_dummy_packet(seq=2)]
    cap = PacketCaptureService(synthetic_stream=packets)
    runner = LivePipelineRunner(capture_service=cap, mode=LiveMode.DRY_RUN, queue_capacity=50)
    rep = runner.run()

    # Invariants
    assert rep["zero_network_mutation_guaranteed"] is True
    assert rep["mode"] == LiveMode.DRY_RUN.value

    # Observability blocks
    assert "health_report" in rep
    assert rep["health_report"]["state"] == "HEALTHY"

    assert "queue_metrics" in rep
    assert rep["queue_metrics"]["capacity"] == 50

    assert "capture_metrics" in rep
    assert rep["capture_metrics"]["packets_captured"] == 2
    assert rep["capture_metrics"]["source_type"] == "synthetic"

    assert "flow_builder_metrics" in rep
    assert rep["flow_builder_metrics"]["completed_flows"] >= 1
    assert "max_active_flow_watermark" in rep["flow_builder_metrics"]

    assert "processing_metrics" in rep
    assert rep["processing_metrics"]["flows_processed"] >= 1

    assert "safety_metrics" in rep
    assert "failsafe_allow_events" in rep["safety_metrics"]

    assert "audit_metrics" in rep
    assert rep["audit_metrics"]["audit_cards_generated"] >= 1
    assert rep["audit_metrics"]["audit_coverage_pct"] == 100.0
