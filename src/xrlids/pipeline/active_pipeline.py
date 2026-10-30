"""Active Inference Pipeline for XRL-IDARS (Phases 5, 7, 8, 10, 11, 13).

Integrates:
1. Feature extraction & contract validation (FeatureSchemaValidator)
2. Primary ML Champion detection (ModelManager)
3. Deterministic protocol rules (RuleEngine)
4. Hybrid decision arbitration (HybridDecisionEngine)
5. Source-IP activity tracking (SourceActivityTracker)
6. Real-time TreeSHAP local explanations (TreeSHAPExplainer)
7. Autonomous DQN response policy (DQNResponseService)
8. Deterministic safety gate (DeterministicSafetyGate)
9. Event publishing & persistent audit logging (EventManager)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Mapping

import numpy as np

from xrlids.events.manager import EventManager
from xrlids.events.schema import SecurityEvent
from xrlids.explainability.explainer import ExplanationResult, TreeSHAPExplainer
from xrlids.flow.canonical_builder import CanonicalFlow
from xrlids.models.manager import FlowInferenceResult, ModelManager
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.service import DQNResponseService, ResponseRecommendation
from xrlids.response.types import Action
from xrlids.rules.engine import RuleEngine, RuleMatch
from xrlids.rules.hybrid import HybridDecision, HybridDecisionEngine
from xrlids.tracking.source_tracker import EscalationDecision, SourceActivityTracker
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """Comprehensive outcome of end-to-end flow evaluation."""

    flow_id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: int
    features: dict[str, float]

    # Model & Detection
    inference: FlowInferenceResult
    rule_matches: list[RuleMatch]
    hybrid: HybridDecision
    source_decision: EscalationDecision

    # Explainability
    explanation: ExplanationResult | None

    # Response & Safety
    response: ResponseRecommendation
    enforced_action: Action
    safety_override: bool
    override_reason: str | None

    # Telemetry
    total_pipeline_time_ms: float
    security_event: SecurityEvent

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "features": self.features,
            "inference": self.inference.to_dict(),
            "rule_matches": [asdict(r) for r in self.rule_matches],
            "hybrid": self.hybrid.to_dict(),
            "source_decision": asdict(self.source_decision),
            "explanation": self.explanation.to_dict() if self.explanation else None,
            "response": self.response.to_dict(),
            "enforced_action": self.enforced_action.name,
            "safety_override": self.safety_override,
            "override_reason": self.override_reason,
            "total_pipeline_time_ms": self.total_pipeline_time_ms,
            "event_id": self.security_event.event_id,
        }


class ActiveInferencePipeline:
    """Production-grade active pipeline processing network flows."""

    def __init__(
        self,
        model_manager: ModelManager | None = None,
        event_manager: EventManager | None = None,
        explain_all: bool = False,
        explain_threat_threshold: float = 0.40,
    ) -> None:
        self.model_manager = model_manager or ModelManager()
        self.event_manager = event_manager or EventManager()
        self.explain_all = explain_all
        self.explain_threat_threshold = explain_threat_threshold

        self.rule_engine = RuleEngine()
        self.hybrid_engine = HybridDecisionEngine()
        self.source_tracker = SourceActivityTracker()
        self.response_service = DQNResponseService()
        self.safety_gate = DeterministicSafetyGate()

        # Initialize TreeSHAP explainer with champion model
        self.explainer = TreeSHAPExplainer(
            model=self.model_manager.model,
            preprocessor=self.model_manager.preprocessor,
        )

        self._step_counter = 0

    def process_flow(
        self,
        flow_or_features: CanonicalFlow | Mapping[str, Any],
        source_ip: str = "192.168.1.100",
        dest_ip: str = "10.0.0.1",
        source_port: int = 12345,
        dest_port: int = 80,
        protocol: int = 6,
        flow_id: str | None = None,
        timestamp: float | None = None,
        explain: bool | None = None,
    ) -> PipelineResult:
        """Process a completed flow end-to-end through all tiers."""
        t0 = time.perf_counter()
        self._step_counter += 1
        current_step = self._step_counter
        ts = timestamp or time.time()

        # 1. Extract endpoint metadata and features
        if isinstance(flow_or_features, CanonicalFlow):
            flow = flow_or_features
            features = flow.to_features(validate=True)
            source_ip = flow.source_first_ip or flow.key.endpoint_a
            dest_ip = flow.dest_first_ip or flow.key.endpoint_b
            source_port = flow.source_first_port or flow.key.port_a
            dest_port = flow.dest_first_port or flow.key.port_b
            protocol = flow.key.protocol
            flow_obj = flow
        else:
            features = dict(flow_or_features)
            flow_obj = None

        fid = flow_id or f"flow-{int(ts * 1000)}-{self._step_counter}"

        # 2. Perception Tier: Champion ML Inference
        infer_result = self.model_manager.predict_flow(features, flow_id=fid)
        attack_score = infer_result.attack_score

        # 3. Rule Tier: Deterministic Protocol Analysis
        if flow_obj is not None:
            rule_matches = self.rule_engine.evaluate_flow(flow_obj)
        else:
            rule_matches = self.rule_engine.evaluate_features(
                features,
                endpoints={"src_ip": source_ip, "dst_ip": dest_ip},
            )

        # 4. Hybrid Arbitration: Reconcile ML and Rules
        hybrid_dec = self.hybrid_engine.evaluate(
            rf_probability=attack_score,
            rule_matches=rule_matches,
        )

        # 5. Tracking Tier: Source-IP Activity Tracker
        is_suspicious = bool(hybrid_dec.is_attack or attack_score >= 0.50 or len(rule_matches) > 0)
        source_dec = self.source_tracker.record_flow(
            source_ip=source_ip,
            is_suspicious=is_suspicious,
            timestamp=ts,
        )

        # 6. Explainability Tier: TreeSHAP local attribution
        should_explain = (
            explain
            if explain is not None
            else (self.explain_all or attack_score >= self.explain_threat_threshold or len(rule_matches) > 0)
        )
        explanation: ExplanationResult | None = None
        if should_explain:
            try:
                explanation = self.explainer.explain_flow(features, flow_id=fid)
            except Exception as e:
                logger.warning("Could not compute TreeSHAP explanation for %s: %s", fid, e)

        # 7. Decision Tier: DQN Response Recommendation
        flow_bps = float(features.get("flow_bytes_per_s", 0.0))
        rem_cooldown = self.safety_gate.get_remaining_cooldown(source_ip, current_step)

        response_rec = self.response_service.recommend_action(
            attack_score=hybrid_dec.threat_score,
            flow_bytes_per_s=flow_bps,
            host_id=source_ip,
            cooldown_remaining=rem_cooldown,
        )

        # 8. Safety Tier: Deterministic Safety Gate Enforcement
        enforced_act, is_override, override_reason = self.safety_gate.enforce_safety(
            step=current_step,
            flow_id=fid,
            host_id=source_ip,
            proposed_action=response_rec.action,
        )

        # 9. Formulate SecurityEvent
        sec_event = SecurityEvent(
            flow_id=fid,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            features=features,
            detection={
                "model_name": infer_result.model_name,
                "model_type": infer_result.model_type,
                "attack_score": infer_result.attack_score,
                "prediction_label": infer_result.prediction_label,
                "inference_time_ms": infer_result.inference_time_ms,
            },
            rule_matches=[asdict(r) for r in rule_matches],
            hybrid_verdict=hybrid_dec.detection_source if hybrid_dec.is_attack else "BENIGN",
            severity=hybrid_dec.severity,
            source_escalated=source_dec.escalate,
            source_status=self.source_tracker.get_host_status(source_ip, timestamp=ts),
            explanation=explanation.to_dict() if explanation else None,
            response={
                "proposed_action": response_rec.action.name,
                "enforced_action": enforced_act.name,
                "safety_override": is_override,
                "override_reason": override_reason,
                "q_values": response_rec.q_values,
                "best_q_value": response_rec.best_q_value,
                "q_advantage": response_rec.q_advantage_over_next,
                "state_vector": response_rec.state_vector,
                "justification": response_rec.justification,
            },
        )

        # Publish event
        self.event_manager.publish(sec_event)

        t1 = time.perf_counter()
        total_time_ms = (t1 - t0) * 1000.0

        return PipelineResult(
            flow_id=fid,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            features=features,
            inference=infer_result,
            rule_matches=rule_matches,
            hybrid=hybrid_dec,
            source_decision=source_dec,
            explanation=explanation,
            response=response_rec,
            enforced_action=enforced_act,
            safety_override=is_override,
            override_reason=override_reason,
            total_pipeline_time_ms=total_time_ms,
            security_event=sec_event,
        )
