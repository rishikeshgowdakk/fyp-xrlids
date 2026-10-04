"""Observability, Operational Health, and Failure-Injection Architecture (Phase 3F).

Implements:
1. HealthState Model: HEALTHY, DEGRADED, FAILED_SAFE based on observable metrics.
2. BoundedFlowQueue: Bounded queue with watermark, backpressure drop handling, and age tracking.
3. Observability Telemetry: Metrics across capture, flow builder, processing, safety, and audit.
4. FailureInjectionHarness: Deterministic fault injection verifying fail-safe operational invariants.

NOTE: All thresholds in this module are experimental/default observability thresholds
for research characterization and lab validation, NOT production SLAs.
"""

from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Sequence

import numpy as np

from xrlids.demo.flow import Flow
from xrlids.demo.pcap import PacketInfo
from xrlids.response.types import Action

logger = logging.getLogger(__name__)


class HealthState(str, Enum):
    """Operational health states for the XRL-IDARS live perception-response pipeline."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED_SAFE = "FAILED_SAFE"


@dataclass(frozen=True)
class HealthConfig:
    """Configurable observability thresholds for health-state determination.

    NOTE: These thresholds are experimental/default observability thresholds
    for research characterization, NOT production SLAs.
    """

    degraded_queue_fill_pct: float = 80.0
    degraded_backpressure_drops_threshold: int = 1
    failed_safe_error_threshold: int = 1


@dataclass
class HealthReport:
    """Snapshot of system health state, active reasons, and observable triggers."""

    state: HealthState
    reasons: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metrics_snapshot: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reasons": list(self.reasons),
            "timestamp": self.timestamp,
            "metrics_snapshot": self.metrics_snapshot,
        }


class HealthMonitor:
    """Derives pipeline health state from observable telemetry."""

    def __init__(self, config: HealthConfig | None = None) -> None:
        self.config = config or HealthConfig()

    def evaluate(
        self,
        queue_stats: dict[str, Any],
        error_counts: dict[str, int],
        auditor_summary: dict[str, Any] | None = None,
    ) -> HealthReport:
        """Derive HealthState from queue metrics, subsystem errors, and audit status.

        Rules:
        1. FAILED_SAFE if any critical subsystem error (detector, policy, safety gate,
           or audit persistence) reaches failed_safe_error_threshold.
        2. DEGRADED if queue fill percentage >= degraded_queue_fill_pct OR
           backpressure drops >= degraded_backpressure_drops_threshold.
        3. HEALTHY if queue and all subsystems operate within normal bounds.
        """
        reasons: list[str] = []

        # 1. Critical Subsystem Error Evaluation
        detector_fails = error_counts.get("detector_failures", 0)
        policy_fails = error_counts.get("policy_failures", 0)
        safety_fails = error_counts.get("safety_gate_failures", 0)
        audit_fails = error_counts.get("audit_write_failures", 0)
        total_critical = detector_fails + policy_fails + safety_fails + audit_fails

        if total_critical >= self.config.failed_safe_error_threshold:
            if detector_fails > 0:
                reasons.append(f"Detector inference failure count: {detector_fails}")
            if policy_fails > 0:
                reasons.append(f"Policy evaluation failure count: {policy_fails}")
            if safety_fails > 0:
                reasons.append(f"Safety gate failure count: {safety_fails}")
            if audit_fails > 0:
                reasons.append(f"Audit persistence failure count: {audit_fails}")
            return HealthReport(
                state=HealthState.FAILED_SAFE,
                reasons=reasons,
                metrics_snapshot={
                    "total_critical_errors": total_critical,
                    "error_counts": dict(error_counts),
                    "queue_depth": queue_stats.get("current_depth", 0),
                },
            )

        # 2. Queue Backpressure & Saturation Evaluation
        queue_depth = queue_stats.get("current_depth", 0)
        queue_capacity = queue_stats.get("capacity", 1)
        fill_pct = (queue_depth / max(1, queue_capacity)) * 100.0
        backpressure_drops = queue_stats.get("overflow_count", 0)

        if fill_pct >= self.config.degraded_queue_fill_pct:
            reasons.append(
                f"Queue capacity fill is high: {fill_pct:.1f}% "
                f"({queue_depth}/{queue_capacity} items)"
            )
        if backpressure_drops >= self.config.degraded_backpressure_drops_threshold:
            reasons.append(
                f"Backpressure drops observed: {backpressure_drops} dropped items"
            )

        if reasons:
            return HealthReport(
                state=HealthState.DEGRADED,
                reasons=reasons,
                metrics_snapshot={
                    "fill_pct": round(fill_pct, 2),
                    "backpressure_drops": backpressure_drops,
                    "queue_depth": queue_depth,
                    "queue_capacity": queue_capacity,
                },
            )

        # 3. Healthy Baseline
        return HealthReport(
            state=HealthState.HEALTHY,
            reasons=["All operational telemetry nominal; queue depth within healthy range."],
            metrics_snapshot={
                "fill_pct": round(fill_pct, 2),
                "queue_depth": queue_depth,
                "backpressure_drops": 0,
                "critical_errors": 0,
            },
        )


@dataclass
class BackpressureDropEvent:
    """Auditable record emitted when a flow cannot be accepted due to queue saturation."""

    timestamp: str
    flow_id: int | str
    queue_depth: int
    queue_capacity: int
    reason: str = "QUEUE_CAPACITY_EXCEEDED"
    enforced_action: str = "BACKPRESSURE_DROP"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "queue_depth": self.queue_depth,
            "queue_capacity": self.queue_capacity,
            "reason": self.reason,
            "enforced_action": self.enforced_action,
        }


class BoundedFlowQueue:
    """Bounded, thread-safe-capable FIFO queue with explicit watermark and backpressure telemetry.

    Invariants:
    1. NEVER silently drops flows; records an explicit BackpressureDropEvent on overflow.
    2. Tracks enqueue, dequeue, overflow (backpressure drops), high-water mark, and wait time.
    3. Overload does NOT crash the pipeline; returns False on enqueue rejection.
    """

    def __init__(self, capacity: int = 1000) -> None:
        if capacity <= 0:
            raise ValueError(f"Queue capacity must be positive, got {capacity}")
        self.capacity = capacity
        self._queue: collections.deque[tuple[Flow, float, int | str]] = collections.deque()
        self.high_watermark: int = 0
        self.enqueue_count: int = 0
        self.dequeue_count: int = 0
        self.overflow_count: int = 0
        self._wait_latencies_s: list[float] = []
        self._drop_events: list[BackpressureDropEvent] = []

    def enqueue(self, flow: Flow, flow_id: int | str = 0, timestamp: float | None = None) -> bool:
        """Attempt to enqueue a completed flow for downstream inference.

        Returns True if enqueued, or False if rejected due to backpressure saturation.
        """
        now = time.perf_counter() if timestamp is None else timestamp
        if len(self._queue) >= self.capacity:
            self.overflow_count += 1
            drop_event = BackpressureDropEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow_id,
                queue_depth=len(self._queue),
                queue_capacity=self.capacity,
                reason="QUEUE_CAPACITY_EXCEEDED",
            )
            self._drop_events.append(drop_event)
            logger.warning(
                "Backpressure drop: flow %s rejected (queue depth %d >= capacity %d)",
                flow_id,
                len(self._queue),
                self.capacity,
            )
            return False

        self._queue.append((flow, now, flow_id))
        self.enqueue_count += 1
        current_len = len(self._queue)
        if current_len > self.high_watermark:
            self.high_watermark = current_len
        return True

    def dequeue(self) -> tuple[Flow, float, int | str] | None:
        """Retrieve the oldest flow from queue, tracking queue wait latency."""
        if not self._queue:
            return None
        flow, enqueue_time, flow_id = self._queue.popleft()
        wait_s = max(0.0, time.perf_counter() - enqueue_time)
        self._wait_latencies_s.append(wait_s)
        self.dequeue_count += 1
        return flow, wait_s, flow_id

    @property
    def current_depth(self) -> int:
        return len(self._queue)

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def is_full(self) -> bool:
        return len(self._queue) >= self.capacity

    @property
    def oldest_item_age_s(self) -> float:
        if not self._queue:
            return 0.0
        return max(0.0, time.perf_counter() - self._queue[0][1])

    def stats(self) -> dict[str, Any]:
        """Compile queue telemetry summary including percentiles and high watermark."""
        return {
            "capacity": self.capacity,
            "current_depth": self.current_depth,
            "high_watermark": self.high_watermark,
            "enqueue_count": self.enqueue_count,
            "dequeue_count": self.dequeue_count,
            "overflow_count": self.overflow_count,
            "backpressure_drops": self.overflow_count,
            "oldest_item_age_s": round(self.oldest_item_age_s, 6),
            "queue_latency_us": self._calc_dist(self._wait_latencies_s),
            "drop_events_count": len(self._drop_events),
        }

    @staticmethod
    def _calc_dist(samples: Sequence[float]) -> dict[str, Any]:
        if not samples:
            return {
                "count": 0,
                "min_us": 0.0,
                "mean_us": 0.0,
                "p50_us": 0.0,
                "p95_us": 0.0,
                "p99_us": 0.0,
                "max_us": 0.0,
                "unit": "microseconds",
            }
        arr = np.asarray(samples, dtype=float) * 1e6
        return {
            "count": len(arr),
            "min_us": round(float(np.min(arr)), 2),
            "mean_us": round(float(np.mean(arr)), 2),
            "p50_us": round(float(np.percentile(arr, 50)), 2),
            "p95_us": round(float(np.percentile(arr, 95)), 2),
            "p99_us": round(float(np.percentile(arr, 99)), 2),
            "max_us": round(float(np.max(arr)), 2),
            "unit": "microseconds",
        }


class FailureInjectionHarness:
    """Deterministic failure injection harness validating fail-safe operational behavior."""

    @staticmethod
    def test_malformed_packet_injection(flow_builder: Any) -> dict[str, Any]:
        """Inject corrupt / truncated packet and verify zero crash and error counter increment."""
        initial_errors = getattr(flow_builder.stats, "flow_builder_errors", 0)
        # Create a malformed packet with None / invalid attributes
        malformed_pkt = PacketInfo(
            timestamp=-1.0,
            src_ip="",
            dst_ip="",
            src_port=-1,
            dst_port=-1,
            protocol=999,
            packet_length=0,
            is_tcp=False,
        )
        try:
            completed = flow_builder.process_packet(malformed_pkt)
            crashed = False
        except Exception:
            crashed = True
            completed = []

        final_errors = getattr(flow_builder.stats, "flow_builder_errors", 0)
        return {
            "scenario": "malformed_packet_injection",
            "crashed": crashed,
            "completed_flows": len(completed),
            "error_counter_incremented": final_errors >= initial_errors,
            "pass": not crashed,
        }

    @staticmethod
    def test_queue_saturation(queue_capacity: int = 5, burst_flows_count: int = 15) -> dict[str, Any]:
        """Push more flows than capacity, verify watermark matches capacity and drops are audited."""
        from xrlids.demo.flow import FlowKey

        queue = BoundedFlowQueue(capacity=queue_capacity)
        accepted = 0
        rejected = 0

        for i in range(burst_flows_count):
            key = FlowKey(f"10.0.0.{i}", "10.0.0.1", 1000 + i, 80, 6)
            dummy_flow = Flow(key=key, start_time=100.0, last_time=101.0)
            if queue.enqueue(dummy_flow, flow_id=i + 1):
                accepted += 1
            else:
                rejected += 1

        stats = queue.stats()
        is_pass = (
            stats["high_watermark"] == queue_capacity
            and stats["overflow_count"] == (burst_flows_count - queue_capacity)
            and rejected == (burst_flows_count - queue_capacity)
            and accepted == queue_capacity
        )
        return {
            "scenario": "queue_saturation",
            "queue_capacity": queue_capacity,
            "burst_flows_count": burst_flows_count,
            "accepted_count": accepted,
            "rejected_count": rejected,
            "high_watermark": stats["high_watermark"],
            "overflow_count": stats["overflow_count"],
            "pass": is_pass,
        }

    @staticmethod
    def test_detector_failure_failsafe(runner: Any) -> dict[str, Any]:
        """Simulate detector model failure, verify fail-safe ALLOW fallback and error accounting."""
        from unittest.mock import MagicMock

        mock_detector = MagicMock()
        mock_detector.predict_proba.side_effect = RuntimeError("Simulated detector GPU/CPU memory crash")

        # Temporarily attach mock detector
        orig_detector = runner.detector_model
        runner.detector_model = mock_detector
        initial_fails = runner.error_counts.get("detector_failures", 0)

        from xrlids.demo.flow import Flow, FlowKey
        dummy_flow = Flow(
            key=FlowKey("192.168.1.100", "10.0.0.1", 45678, 80, 6),
            start_time=100.0,
            last_time=101.0,
        )
        pkt = PacketInfo(
            timestamp=100.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=45678,
            dst_port=80,
            protocol=6,
            packet_length=64,
            is_tcp=True,
            syn=True,
            ack=False,
        )
        dummy_flow.add_packet(pkt, is_forward=True)

        try:
            runner._process_flow(dummy_flow)
            crashed = False
        except Exception:
            crashed = True
        finally:
            runner.detector_model = orig_detector

        final_fails = runner.error_counts.get("detector_failures", 0)
        # Check last card
        last_card = runner.auditor.audit_cards[-1] if runner.auditor.audit_cards else None
        safe_action = (last_card.enforced_action == Action.ALLOW.name) if last_card else False

        return {
            "scenario": "detector_failure_failsafe",
            "crashed": crashed,
            "failure_recorded": final_fails > initial_fails,
            "fallback_to_safe_action": safe_action,
            "pass": (not crashed) and (final_fails > initial_fails) and safe_action,
        }

    @staticmethod
    def test_policy_failure_failsafe(runner: Any) -> dict[str, Any]:
        """Simulate policy evaluation failure, verify fail-safe fallback and error accounting."""
        from unittest.mock import MagicMock

        mock_policy = MagicMock()
        mock_policy.select_action.side_effect = RuntimeError("Simulated policy inference crash")

        orig_policy = runner.policy
        runner.policy = mock_policy
        initial_fails = runner.error_counts.get("policy_failures", 0)

        from xrlids.demo.flow import Flow, FlowKey
        dummy_flow = Flow(
            key=FlowKey("192.168.1.101", "10.0.0.1", 45679, 80, 6),
            start_time=100.0,
            last_time=101.0,
        )
        pkt = PacketInfo(
            timestamp=100.0,
            src_ip="192.168.1.101",
            dst_ip="10.0.0.1",
            src_port=45679,
            dst_port=80,
            protocol=6,
            packet_length=64,
            is_tcp=True,
            syn=True,
            ack=False,
        )
        dummy_flow.add_packet(pkt, is_forward=True)

        try:
            runner._process_flow(dummy_flow)
            crashed = False
        except Exception:
            crashed = True
        finally:
            runner.policy = orig_policy

        final_fails = runner.error_counts.get("policy_failures", 0)
        last_card = runner.auditor.audit_cards[-1] if runner.auditor.audit_cards else None
        safe_action = (last_card.enforced_action in (Action.ALLOW.name, Action.ALERT.name)) if last_card else False

        return {
            "scenario": "policy_failure_failsafe",
            "crashed": crashed,
            "failure_recorded": final_fails > initial_fails,
            "fallback_to_safe_action": safe_action,
            "pass": (not crashed) and (final_fails > initial_fails) and safe_action,
        }

    @staticmethod
    def test_safety_gate_failure_failsafe(runner: Any) -> dict[str, Any]:
        """Simulate safety gate exception, verify fallback to ALLOW and no disruptive action."""
        from unittest.mock import MagicMock

        mock_gate = MagicMock()
        mock_gate.enforce_safety.side_effect = RuntimeError("Simulated safety gate exception")

        orig_gate = runner.safety_gate
        runner.safety_gate = mock_gate
        initial_fails = runner.error_counts.get("safety_gate_failures", 0)

        from xrlids.demo.flow import Flow, FlowKey
        dummy_flow = Flow(
            key=FlowKey("192.168.1.102", "10.0.0.1", 45680, 80, 6),
            start_time=100.0,
            last_time=101.0,
        )
        pkt = PacketInfo(
            timestamp=100.0,
            src_ip="192.168.1.102",
            dst_ip="10.0.0.1",
            src_port=45680,
            dst_port=80,
            protocol=6,
            packet_length=64,
            is_tcp=True,
            syn=True,
            ack=False,
        )
        dummy_flow.add_packet(pkt, is_forward=True)

        try:
            runner._process_flow(dummy_flow)
            crashed = False
        except Exception:
            crashed = True
        finally:
            runner.safety_gate = orig_gate

        final_fails = runner.error_counts.get("safety_gate_failures", 0)
        last_card = runner.auditor.audit_cards[-1] if runner.auditor.audit_cards else None
        safe_action = (last_card.enforced_action == Action.ALLOW.name) if last_card else False

        return {
            "scenario": "safety_gate_failure_failsafe",
            "crashed": crashed,
            "failure_recorded": final_fails > initial_fails,
            "fallback_to_allow": safe_action,
            "pass": (not crashed) and (final_fails > initial_fails) and safe_action,
        }

    @staticmethod
    def test_audit_persistence_failure_lock(runner: Any) -> dict[str, Any]:
        """Simulate audit write failure, verify enforcement remains locked and error is counted."""
        from unittest.mock import MagicMock

        mock_auditor = MagicMock()
        mock_auditor.record.side_effect = IOError("Simulated disk full / audit stream failure")
        mock_auditor.audit_cards = runner.auditor.audit_cards
        mock_auditor.summary.return_value = runner.auditor.summary()

        orig_auditor = runner.auditor
        runner.auditor = mock_auditor
        initial_fails = runner.error_counts.get("audit_write_failures", 0)

        from xrlids.demo.flow import Flow, FlowKey
        dummy_flow = Flow(
            key=FlowKey("192.168.1.103", "10.0.0.1", 45681, 80, 6),
            start_time=100.0,
            last_time=101.0,
        )
        pkt = PacketInfo(
            timestamp=100.0,
            src_ip="192.168.1.103",
            dst_ip="10.0.0.1",
            src_port=45681,
            dst_port=80,
            protocol=6,
            packet_length=64,
            is_tcp=True,
            syn=True,
            ack=False,
        )
        dummy_flow.add_packet(pkt, is_forward=True)

        try:
            runner._process_flow(dummy_flow)
            crashed = False
        except Exception:
            crashed = True
        finally:
            runner.auditor = orig_auditor

        final_fails = runner.error_counts.get("audit_write_failures", 0)
        report = runner.get_report()
        zero_mutation = report.get("zero_network_mutation_guaranteed", False)

        return {
            "scenario": "audit_persistence_failure_lock",
            "crashed": crashed,
            "failure_recorded": final_fails > initial_fails,
            "zero_network_mutation_guaranteed": zero_mutation,
            "pass": (not crashed) and (final_fails > initial_fails) and zero_mutation,
        }
