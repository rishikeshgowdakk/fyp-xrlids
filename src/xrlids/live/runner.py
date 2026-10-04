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

        self.capture_service = capture_service
        self.flow_builder = flow_builder or LiveFlowBuilder()
        self.detector_model = detector_model
        self.policy = policy
        self.safety_gate = safety_gate or DeterministicSafetyGate()
        self.state_builder = state_builder or StateBuilder()
        self.explainer = explainer
        self.mode = mode
        self.auditor = DryRunAuditor()
        self._flow_index = 0

    def run(self) -> dict[str, Any]:
        """Stream packets, assemble flows, score threats, and evaluate response policy."""
        self.auditor = DryRunAuditor()
        self._flow_index = 0
        self.safety_gate.reset()
        self.state_builder.reset()

        for pkt in self.capture_service.stream_packets():
            completed_flows = self.flow_builder.process_packet(pkt)
            for flow in completed_flows:
                self._process_flow(flow)

        # Flush any remaining active flows at stream completion
        for flow in self.flow_builder.flush_all():
            self._process_flow(flow)

        return self.get_report()

    def _process_flow(self, flow: Flow) -> None:
        """Process a completed flow through detector, state builder, and response policy."""
        self._flow_index += 1
        flow_id = self._flow_index
        src_ep = f"{flow.source_first_ip}:{flow.source_first_port}"
        dst_ep = f"{flow.dest_first_ip}:{flow.dest_first_port}"

        # 1. Compute R10 Feature Vector
        try:
            r10_dict = flow.to_features()
            feat_vec = flow.feature_vector().reshape(1, -1)
        except Exception as err:
            logger.error("Feature calculation error for flow %d: %s", flow_id, err)
            self.auditor.inference_failures += 1
            return

        # 2. Detector Scoring (Phase 1 Frozen Detector)
        score = 0.0
        if self.detector_model is not None:
            try:
                if hasattr(self.detector_model, "predict_proba"):
                    score = float(self.detector_model.predict_proba(feat_vec)[0, 1])
                elif hasattr(self.detector_model, "predict"):
                    score = float(self.detector_model.predict(feat_vec)[0])
            except Exception as err:
                logger.error("Detector inference error for flow %d: %s", flow_id, err)
                self.auditor.inference_failures += 1
                score = 0.0  # Fail-safe default

        # If in OBSERVE mode, we do not evaluate policy or safety gate
        if self.mode == LiveMode.OBSERVE:
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
            state_vec = np.zeros(6, dtype=np.float32)

        # 4. Response Policy Action Proposal
        proposed_action = Action.ALLOW
        if self.policy is not None:
            try:
                if hasattr(self.policy, "select_action"):
                    # DQN agent
                    act_idx = self.policy.select_action(state_vec, evaluation=True)
                    proposed_action = Action(act_idx)
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
                proposed_action = Action.ALLOW  # Fail-safe default

        # 5. Deterministic Safety Gate Invariant Enforcement
        try:
            enforced_action, override_applied, override_reason = self.safety_gate.enforce_safety(
                step=self._flow_index,
                flow_id=flow_id,
                host_id=flow.source_first_ip,
                proposed_action=proposed_action,
            )
        except Exception as err:
            logger.error("Safety gate error for flow %d: %s", flow_id, err)
            self.auditor.inference_failures += 1
            enforced_action = Action.ALLOW  # Fail-safe default
            override_applied = True
            override_reason = f"Safety gate exception: {err}"

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
        )
        self.auditor.record(card)

    def get_report(self) -> dict[str, Any]:
        """Compile execution statistics, audit counts, and zero-mutation verification."""
        return {
            "mode": self.mode.value,
            "flows_processed": self._flow_index,
            "capture_stats": self.capture_service.stats.to_dict(),
            "flow_builder_stats": self.flow_builder.stats.to_dict(),
            "auditor_summary": self.auditor.summary(),
            "zero_network_mutation_guaranteed": True,
        }
