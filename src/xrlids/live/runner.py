"""Live Pipeline Runner and Dry-Run Autonomous Response Engine (Phase 3).

Orchestrates the real-time or streaming pipeline:
PacketCaptureService -> LiveFlowBuilder (D-006) -> R10 Features
  -> Frozen Phase 1 Detector -> Causal 6D State -> Response Policy
  -> Deterministic Safety Gate -> Dry-Run Audit Logging

Operating Modes:
- OBSERVE: Passive flow building and detection scoring. No actions evaluated.
- DRY_RUN: Full end-to-end evaluation with deterministic safety gate and audit cards.
           STRICT GUARANTEE: ZERO network mutations (no iptables, nftables, routes, drops).
- CONTROLLED_ENFORCEMENT: Explicitly locked pending full rollback and precondition verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np

from xrlids.demo.flow import Flow
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES
from xrlids.live.capture import PacketCaptureService
from xrlids.live.flow_builder import LiveFlowBuilder
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode

logger = logging.getLogger(__name__)


class LiveMode(str, Enum):
    """Operational mode governing autonomous response actuation."""

    OBSERVE = "OBSERVE"
    DRY_RUN = "DRY_RUN"
    CONTROLLED_ENFORCEMENT = "CONTROLLED_ENFORCEMENT"


@dataclass
class DryRunAuditCard:
    """Immutable audit record for an autonomous response evaluation."""

    timestamp: str
    flow_id: int
    src_endpoint: str
    dst_endpoint: str
    protocol: int
    packet_count: int
    duration_ms: float
    threat_score: float
    state_vector: list[float]
    proposed_action: str
    enforced_action: str
    safety_override: bool
    override_reason: str | None
    r10_features: dict[str, float]
    top_explanations: dict[str, float] = field(default_factory=dict)
    inference_source: str = "RANDOM_FOREST"
    rf_score: float | None = None
    lstm_score: float | None = None
    fusion_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "src_endpoint": self.src_endpoint,
            "dst_endpoint": self.dst_endpoint,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "duration_ms": round(self.duration_ms, 2),
            "threat_score": round(self.threat_score, 4),
            "state_vector": [round(x, 4) for x in self.state_vector],
            "proposed_action": self.proposed_action,
            "enforced_action": self.enforced_action,
            "safety_override": self.safety_override,
            "override_reason": self.override_reason,
            "r10_features": {k: round(v, 4) for k, v in self.r10_features.items()},
            "top_explanations": {k: round(v, 4) for k, v in self.top_explanations.items()},
            "inference_source": self.inference_source,
            "rf_score": round(self.rf_score, 4) if self.rf_score is not None else None,
            "lstm_score": round(self.lstm_score, 4) if self.lstm_score is not None else None,
            "fusion_score": round(self.fusion_score, 4) if self.fusion_score is not None else None,
        }


@dataclass
class DryRunAuditor:
    """Maintains an auditable, append-only record of response decisions without mutating system state."""

    audit_cards: list[DryRunAuditCard] = field(default_factory=list)
    action_counts_proposed: dict[str, int] = field(
        default_factory=lambda: {"ALLOW": 0, "ALERT": 0, "RATE_LIMIT": 0, "ISOLATE": 0}
    )
    action_counts_enforced: dict[str, int] = field(
        default_factory=lambda: {"ALLOW": 0, "ALERT": 0, "RATE_LIMIT": 0, "ISOLATE": 0}
    )
    total_safety_overrides: int = 0
    inference_failures: int = 0

    def record(self, card: DryRunAuditCard) -> None:
        self.audit_cards.append(card)
        self.action_counts_proposed[card.proposed_action] = (
            self.action_counts_proposed.get(card.proposed_action, 0) + 1
        )
        self.action_counts_enforced[card.enforced_action] = (
            self.action_counts_enforced.get(card.enforced_action, 0) + 1
        )
        if card.safety_override:
            self.total_safety_overrides += 1

    def summary(self) -> dict[str, Any]:
        return {
            "total_decisions": len(self.audit_cards),
            "action_counts_proposed": dict(self.action_counts_proposed),
            "action_counts_enforced": dict(self.action_counts_enforced),
            "total_safety_overrides": self.total_safety_overrides,
            "override_rate": round(
                self.total_safety_overrides / max(1, len(self.audit_cards)), 4
            ),
            "inference_failures": self.inference_failures,
        }


class LivePipelineRunner:
    """Executes the live network validation pipeline under safe operational constraints."""

    def __init__(
        self,
        capture_service: PacketCaptureService,
        flow_builder: LiveFlowBuilder | None = None,
        detector_model: Any | None = None,
        policy: Any | None = None,
        safety_gate: DeterministicSafetyGate | None = None,
        state_builder: StateBuilder | None = None,
        explainer: Any | None = None,
        mode: LiveMode = LiveMode.OBSERVE,
    ) -> None:
        if mode == LiveMode.CONTROLLED_ENFORCEMENT:
            raise RuntimeError(
                "Controlled enforcement mode is locked pending verification of the complete "
                "Phase 3 precondition chain: feature parity PASS -> replay PASS -> "
                "dry-run PASS -> safety tests PASS -> rollback PASS."
            )

@dataclass
class LatencyTracker:
    """Collects high-resolution monotonic latencies across pipeline components."""

    capture_latencies: list[float] = field(default_factory=list)
    flow_assembly_latencies: list[float] = field(default_factory=list)
    feature_construction_latencies: list[float] = field(default_factory=list)
    detector_latencies: list[float] = field(default_factory=list)
    policy_latencies: list[float] = field(default_factory=list)
    safety_gate_latencies: list[float] = field(default_factory=list)
    flow_pipeline_latencies: list[float] = field(default_factory=list)
    packet_processing_latencies: list[float] = field(default_factory=list)

    def record(self, component: str, duration_s: float) -> None:
        """Record an execution duration in seconds."""
        if component == "capture":
            self.capture_latencies.append(duration_s)
        elif component == "flow_assembly":
            self.flow_assembly_latencies.append(duration_s)
        elif component == "feature_construction":
            self.feature_construction_latencies.append(duration_s)
        elif component == "detector_inference":
            self.detector_latencies.append(duration_s)
        elif component == "policy_evaluation":
            self.policy_latencies.append(duration_s)
        elif component == "safety_gate":
            self.safety_gate_latencies.append(duration_s)
        elif component == "flow_pipeline":
            self.flow_pipeline_latencies.append(duration_s)
        elif component == "packet_processing":
            self.packet_processing_latencies.append(duration_s)

    def summary(self) -> dict[str, dict[str, Any]]:
        """Return distribution percentiles (P50, P95, P99, min, max, mean, count) in microseconds."""
        return {
            "packet_capture": self._calc_dist(self.capture_latencies),
            "flow_assembly": self._calc_dist(self.flow_assembly_latencies),
            "feature_construction": self._calc_dist(self.feature_construction_latencies),
            "detector_inference": self._calc_dist(self.detector_latencies),
            "policy_evaluation": self._calc_dist(self.policy_latencies),
            "safety_gate": self._calc_dist(self.safety_gate_latencies),
            "flow_pipeline_e2e": self._calc_dist(self.flow_pipeline_latencies),
            "packet_processing_total": self._calc_dist(self.packet_processing_latencies),
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
        arr = np.asarray(samples, dtype=float) * 1e6  # seconds to microseconds
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


from xrlids.live.observability import (
    BackpressureDropEvent,
    BoundedFlowQueue,
    HealthConfig,
    HealthMonitor,
    HealthReport,
    HealthState,
)


class LivePipelineRunner:
    """Executes the live network validation pipeline under safe operational constraints."""

    def __init__(
        self,
        capture_service: PacketCaptureService,
        flow_builder: LiveFlowBuilder | None = None,
        detector_model: Any | None = None,
        policy: Any | None = None,
        safety_gate: DeterministicSafetyGate | None = None,
        state_builder: StateBuilder | None = None,
        explainer: Any | None = None,
        mode: LiveMode = LiveMode.OBSERVE,
        queue_capacity: int = 1000,
        health_config: HealthConfig | None = None,
        benchmark: str = "cicids2017",
        enable_lstm_fusion: bool = True,
    ) -> None:
        if mode == LiveMode.CONTROLLED_ENFORCEMENT:
            raise RuntimeError(
                "Controlled enforcement mode is locked pending verification of the complete "
                "Phase 3 precondition chain: feature parity PASS -> replay PASS -> "
                "dry-run PASS -> safety tests PASS -> rollback PASS."
            )

        self.capture_service = capture_service
        self.flow_builder = flow_builder or LiveFlowBuilder()
        if detector_model is None:
            try:
                from xrlids.models.inference_service import DEFAULT_INFERENCE_SERVICE
                self.detector_model = DEFAULT_INFERENCE_SERVICE
            except Exception:
                self.detector_model = None
        else:
            self.detector_model = detector_model
        self.policy = policy
        self.safety_gate = safety_gate or DeterministicSafetyGate()
        self.state_builder = state_builder or StateBuilder()
        self.explainer = explainer
        self.mode = mode
        self.queue_capacity = queue_capacity
        self.flow_queue = BoundedFlowQueue(capacity=queue_capacity)
        self.health_monitor = HealthMonitor(config=health_config)
        self.auditor = DryRunAuditor()
        self.latency_tracker = LatencyTracker()
        self.benchmark = benchmark
        self.enable_lstm_fusion = enable_lstm_fusion
        self.error_counts: dict[str, int] = {
            "detector_failures": 0,
            "policy_failures": 0,
            "safety_gate_failures": 0,
            "audit_write_failures": 0,
            "capture_errors": 0,
            "failsafe_allow_events": 0,
            "failsafe_alert_events": 0,
            "enforcement_lock_violations": 0,
            "backpressure_drops": 0,
        }
        self._latest_audit_timestamp: str | None = None
        self._flow_index = 0
        self._start_time: float = 0.0
        self._stop_time: float = 0.0

    def run(self) -> dict[str, Any]:
        """Stream packets, assemble flows, score threats, and evaluate response policy."""
        import time
        import pandas as pd

        self.auditor = DryRunAuditor()
        self.latency_tracker = LatencyTracker()
        self.flow_queue = BoundedFlowQueue(capacity=self.queue_capacity)
        self.error_counts = {
            "detector_failures": 0,
            "policy_failures": 0,
            "safety_gate_failures": 0,
            "audit_write_failures": 0,
            "capture_errors": 0,
            "failsafe_allow_events": 0,
            "failsafe_alert_events": 0,
            "enforcement_lock_violations": 0,
            "backpressure_drops": 0,
        }
        self._flow_index = 0
        self.safety_gate.reset()
        self.state_builder.reset()
        self._start_time = time.perf_counter()

        t_last_yield = time.perf_counter()
        for pkt in self.capture_service.stream_packets():
            t_now = time.perf_counter()
            self.latency_tracker.record("capture", t_now - t_last_yield)

            t_pkt_start = time.perf_counter()
            t_fa_start = time.perf_counter()
            completed_flows = self.flow_builder.process_packet(pkt)
            t_fa_end = time.perf_counter()
            self.latency_tracker.record("flow_assembly", t_fa_end - t_fa_start)

            for flow in completed_flows:
                self._flow_index += 1
                flow_id = self._flow_index
                if not self.flow_queue.enqueue(flow, flow_id=flow_id):
                    self.error_counts["backpressure_drops"] += 1

            while not self.flow_queue.is_empty():
                item = self.flow_queue.dequeue()
                if item is not None:
                    q_flow, q_wait_s, q_flow_id = item
                    self._process_flow(q_flow, q_flow_id=q_flow_id)

            t_pkt_end = time.perf_counter()
            self.latency_tracker.record("packet_processing", t_pkt_end - t_pkt_start)
            t_last_yield = time.perf_counter()

        # Flush any remaining active flows at stream completion
        for flow in self.flow_builder.flush_all():
            self._flow_index += 1
            flow_id = self._flow_index
            if not self.flow_queue.enqueue(flow, flow_id=flow_id):
                self.error_counts["backpressure_drops"] += 1

        while not self.flow_queue.is_empty():
            item = self.flow_queue.dequeue()
            if item is not None:
                q_flow, q_wait_s, q_flow_id = item
                self._process_flow(q_flow, q_flow_id=q_flow_id)

        self._stop_time = time.perf_counter()
        return self.get_report()

    def _process_flow(self, flow: Flow, q_flow_id: int | None = None) -> None:
        """Process a completed flow through detector, state builder, and response policy."""
        import time
        import pandas as pd

        t_flow_pipeline_start = time.perf_counter()
        if q_flow_id is not None:
            flow_id = q_flow_id
        else:
            self._flow_index += 1
            flow_id = self._flow_index

        src_ep = f"{flow.source_first_ip}:{flow.source_first_port}"
        dst_ep = f"{flow.dest_first_ip}:{flow.dest_first_port}"

        # 1. Compute R10 Feature Vector
        t_feat_start = time.perf_counter()
        try:
            r10_dict = flow.to_features()
            feat_vec = flow.feature_vector().reshape(1, -1)
            feat_df = pd.DataFrame([r10_dict], columns=list(R10_FEATURES))
        except Exception as err:
            logger.error("Feature calculation error for flow %d: %s", flow_id, err)
            self.auditor.inference_failures += 1
            self.error_counts["detector_failures"] += 1
            self.error_counts["failsafe_allow_events"] += 1
            return
        t_feat_end = time.perf_counter()
        self.latency_tracker.record("feature_construction", t_feat_end - t_feat_start)

        # 2. Detector Scoring (Phase 1 Frozen Detector or Unified Inference Service)
        t_det_start = time.perf_counter()
        score = 0.0
        inf_source = "RANDOM_FOREST"
        rf_score = 0.0
        lstm_score: float | None = None
        fusion_score: float | None = None

        if self.detector_model is not None:
            try:
                from xrlids.models.inference_service import UnifiedInferenceService
                if isinstance(self.detector_model, UnifiedInferenceService):
                    # Unified multi-model inference service (RF + session-buffered LSTM + Fusion)
                    session_key = f"{flow.source_first_ip}->{flow.dest_first_ip}"
                    res = self.detector_model.infer(
                        features=r10_dict,
                        session_key=session_key,
                        benchmark=self.benchmark,
                        enable_lstm_fusion=self.enable_lstm_fusion,
                    )
                    score = float(res.attack_score)
                    inf_source = res.inference_source
                    rf_score = float(res.rf_score)
                    lstm_score = float(res.lstm_score) if res.lstm_score is not None else None
                    fusion_score = float(res.fusion_score) if res.fusion_score is not None else None
                elif hasattr(self.detector_model, "predict_proba"):
                    try:
                        res = self.detector_model.predict_proba(feat_df)
                    except Exception:
                        res = self.detector_model.predict_proba(feat_vec)
                    if hasattr(res, "ndim") and res.ndim == 2 and res.shape[1] > 1:
                        score = float(res[0, 1])
                    else:
                        score = float(res[0])
                    rf_score = score
                    inf_source = "RANDOM_FOREST"
                elif hasattr(self.detector_model, "predict"):
                    try:
                        res = self.detector_model.predict(feat_df)
                    except Exception:
                        res = self.detector_model.predict(feat_vec)
                    score = float(res[0])
                    rf_score = score
                    inf_source = "RANDOM_FOREST"
            except Exception as err:
                logger.error("Detector inference error for flow %d: %s", flow_id, err)
                self.auditor.inference_failures += 1
                self.error_counts["detector_failures"] += 1
                self.error_counts["failsafe_allow_events"] += 1
                score = 0.0  # Fail-safe default
        t_det_end = time.perf_counter()
        self.latency_tracker.record("detector_inference", t_det_end - t_det_start)

        # If in OBSERVE mode, we do not evaluate policy or safety gate
        if self.mode == LiveMode.OBSERVE:
            t_flow_pipeline_end = time.perf_counter()
            self.latency_tracker.record("flow_pipeline", t_flow_pipeline_end - t_flow_pipeline_start)
            return

        # 3. State Construction (6D Causal State Vector)
        try:
            bytes_per_s = r10_dict.get("flow_bytes_per_s", 0.0)
            state_vec = self.state_builder.build_state(
                attack_score=score,
                flow_bytes_per_s=bytes_per_s,
            )
        except Exception as err:
            logger.error("State construction error for flow %d: %s", flow_id, err)
            self.auditor.inference_failures += 1
            self.error_counts["policy_failures"] += 1
            self.error_counts["failsafe_allow_events"] += 1
            state_vec = np.zeros(6, dtype=np.float32)

        # 4. Response Policy Action Proposal
        t_pol_start = time.perf_counter()
        proposed_action = Action.ALLOW
        if self.policy is not None:
            try:
                if hasattr(self.policy, "select_action"):
                    # DQN agent
                    res = self.policy.select_action(state_vec, epsilon=0.0)
                    proposed_action = res[0] if isinstance(res, tuple) else Action(res)
                elif hasattr(self.policy, "predict_action"):
                    # Deterministic baseline policy
                    proposed_action = self.policy.predict_action(
                        state=state_vec,
                        attack_score=score,
                        host_id=flow.source_first_ip,
                    )
            except Exception as err:
                logger.error("Policy inference error for flow %d: %s", flow_id, err)
                self.auditor.inference_failures += 1
                self.error_counts["policy_failures"] += 1
                self.error_counts["failsafe_allow_events"] += 1
                proposed_action = Action.ALLOW  # Fail-safe default
        t_pol_end = time.perf_counter()
        self.latency_tracker.record("policy_evaluation", t_pol_end - t_pol_start)

        # 5. Deterministic Safety Gate Invariant Enforcement
        t_sg_start = time.perf_counter()
        try:
            enforced_action, override_applied, override_reason = self.safety_gate.enforce_safety(
                step=flow_id,
                flow_id=flow_id,
                host_id=flow.source_first_ip,
                proposed_action=proposed_action,
            )
        except Exception as err:
            logger.error("Safety gate error for flow %d: %s", flow_id, err)
            self.auditor.inference_failures += 1
            self.error_counts["safety_gate_failures"] += 1
            self.error_counts["failsafe_allow_events"] += 1
            enforced_action = Action.ALLOW  # Fail-safe default
            override_applied = True
            override_reason = f"Safety gate exception: {err}"
        t_sg_end = time.perf_counter()
        self.latency_tracker.record("safety_gate", t_sg_end - t_sg_start)

        # 6. Optional Explainability (TreeSHAP)
        top_explanations: dict[str, float] = {}
        if self.explainer is not None and enforced_action != Action.ALLOW:
            try:
                if hasattr(self.explainer, "explain_flow"):
                    card = self.explainer.explain_flow(feat_vec, score, proposed_action, enforced_action)
                    top_explanations = getattr(card, "top_features", {})
            except Exception as err:
                logger.warning("Explainability error for flow %d: %s", flow_id, err)

        # 7. Record Dry-Run Audit Card (ZERO network mutation guaranteed)
        card = DryRunAuditCard(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow_id,
            src_endpoint=src_ep,
            dst_endpoint=dst_ep,
            protocol=flow.key.protocol,
            packet_count=flow.packet_count,
            duration_ms=flow.duration_ms,
            threat_score=score,
            state_vector=state_vec.tolist(),
            proposed_action=proposed_action.name,
            enforced_action=enforced_action.name,
            safety_override=override_applied,
            override_reason=override_reason,
            r10_features=r10_dict,
            top_explanations=top_explanations,
            inference_source=inf_source,
            rf_score=rf_score,
            lstm_score=lstm_score,
            fusion_score=fusion_score,
        )
        try:
            self.auditor.record(card)
            self._latest_audit_timestamp = card.timestamp
        except Exception as err:
            logger.error("Audit write failure for flow %d: %s", flow_id, err)
            self.error_counts["audit_write_failures"] += 1

        t_flow_pipeline_end = time.perf_counter()
        self.latency_tracker.record("flow_pipeline", t_flow_pipeline_end - t_flow_pipeline_start)

    def get_report(self) -> dict[str, Any]:
        """Compile execution statistics, audit counts, latency distributions, and observability report."""
        dur_s = max(0.0, self._stop_time - self._start_time)
        queue_stats = self.flow_queue.stats()
        health_rep = self.health_monitor.evaluate(
            queue_stats=queue_stats,
            error_counts=self.error_counts,
            auditor_summary=self.auditor.summary(),
        )

        safety_sum = self.safety_gate.summary()
        reasons = safety_sum.get("reasons", {})

        return {
            "mode": self.mode.value,
            "flows_processed": self._flow_index,
            "processing_duration_s": round(dur_s, 6),
            "capture_stats": self.capture_service.stats.to_dict(),
            "flow_builder_stats": self.flow_builder.stats.to_dict(),
            "auditor_summary": self.auditor.summary(),
            "latency_summary": self.latency_tracker.summary(),
            "zero_network_mutation_guaranteed": True,
            "health_report": health_rep.to_dict(),
            "queue_metrics": queue_stats,
            "capture_metrics": {
                "packets_captured": self.capture_service.stats.packets_captured,
                "malformed_packets": self.capture_service.stats.malformed_packets,
                "capture_errors": self.capture_service.stats.errors,
                "capture_duration_s": round(self.capture_service.stats.duration_s, 6),
                "packets_per_second": round(self.capture_service.stats.packets_per_second, 2),
                "source_type": getattr(self.capture_service, "backend", "synthetic"),
            },
            "flow_builder_metrics": {
                "active_flows": self.flow_builder.stats.active_flows_count,
                "completed_flows": self.flow_builder.stats.total_flows_completed,
                "fin_rst_completions": self.flow_builder.stats.flows_completed_fin_rst,
                "timeout_completions": self.flow_builder.stats.flows_completed_timeout,
                "flow_builder_errors": self.flow_builder.stats.flow_builder_errors,
                "max_active_flow_watermark": self.flow_builder.stats.max_active_flow_watermark,
            },
            "processing_metrics": {
                "flows_awaiting_processing": self.flow_queue.current_depth,
                "flows_processed": self._flow_index,
                "inference_failures": self.error_counts.get("detector_failures", 0),
                "policy_failures": self.error_counts.get("policy_failures", 0),
                "safety_gate_failures": self.error_counts.get("safety_gate_failures", 0),
                "processing_latency_us": self.latency_tracker.summary().get("detector_inference", {}),
                "queue_latency_us": queue_stats.get("queue_latency_us", {}),
                "end_to_end_latency_us": self.latency_tracker.summary().get("flow_pipeline_e2e", {}),
            },
            "safety_metrics": {
                "safety_gate_summary": safety_sum,
                "safety_overrides": safety_sum.get("total_overrides", 0),
                "critical_host_overrides": reasons.get("CRITICAL_INFRASTRUCTURE_EXEMPTION", 0),
                "blast_radius_interventions": reasons.get("BLAST_RADIUS_CIRCUIT_BREAKER", 0),
                "cooldown_interventions": reasons.get("MANDATORY_ACTION_COOLDOWN", 0),
                "failsafe_allow_events": self.error_counts.get("failsafe_allow_events", 0),
                "failsafe_alert_events": self.error_counts.get("failsafe_alert_events", 0),
                "enforcement_lock_violations": self.error_counts.get("enforcement_lock_violations", 0),
            },
            "audit_metrics": {
                "audit_cards_generated": len(self.auditor.audit_cards),
                "audit_write_failures": self.error_counts.get("audit_write_failures", 0),
                "audit_coverage_pct": round(len(self.auditor.audit_cards) / max(1, self._flow_index) * 100.0, 2),
                "latest_successful_audit_timestamp": self._latest_audit_timestamp,
            },
        }
