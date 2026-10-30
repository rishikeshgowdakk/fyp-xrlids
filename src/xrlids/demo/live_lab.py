"""Observational-only live lab monitor for real-time intrusion alerting.

Strictly observational: monitors network interfaces or packet streams,
accumulates flows, runs model inference, records per-flow observations,
and emits alerts on attack detections.
NEVER mutates system firewall rules, routing tables, or iptables.
"""

from __future__ import annotations

import logging
import socket
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Generator

from xrlids.demo.flow import Flow, FlowBuilder
from xrlids.demo.pcap import PacketInfo, parse_packet_bytes
from xrlids.demo.replay import FlowPredictionEvent, ReplayEngine
from xrlids.rules.engine import RuleEngine

logger = logging.getLogger(__name__)


import time

@dataclass
class AlertEvent:
    """Security alert emitted on attack detection."""

    timestamp: str
    flow_id: int
    alert_level: str  # "HIGH", "MEDIUM", "LOW"
    confidence: float
    src_endpoint: str
    dst_endpoint: str
    protocol: str
    packet_count: int
    duration_ms: float
    details: dict[str, float]
    ground_truth: str = "UNKNOWN"
    mode: str = "live"  # "live", "pcap", "dataset", "sample"
    deduplicated: bool = False
    rule_triggered: bool = False
    rule_matches: list[str] = field(default_factory=list)
    detection_source: str = "RF"  # "RF", "RF+LSTM_FUSION", "RULE", "HYBRID"
    rf_score: float | None = None
    lstm_score: float | None = None
    fusion_score: float | None = None
    dqn_action: str | None = None
    enforced_action: str | None = None
    safety_override: bool = False
    override_reason: str | None = None


@dataclass
class FlowObservation:
    """Per-flow observation record for every completed flow (benign or attack)."""

    timestamp: str
    flow_id: int
    src_endpoint: str
    dst_endpoint: str
    protocol: str
    packet_count: int
    duration_ms: float
    attack_score: float
    prediction_class: int
    prediction_label: str  # "BENIGN" or "ATTACK" at the research threshold
    is_alert: bool
    ground_truth: str = "UNKNOWN"
    features: dict[str, float] | None = None
    mode: str = "live"  # "live", "pcap", "dataset", "sample"
    is_simulated: bool = False
    rule_triggered: bool = False
    rule_matches: list[str] = field(default_factory=list)
    detection_source: str = "NONE"  # "RF", "RF+LSTM_FUSION", "RULE", "HYBRID", "NONE"
    rf_score: float | None = None
    lstm_score: float | None = None
    fusion_score: float | None = None
    dqn_action: str | None = None
    enforced_action: str | None = None
    safety_override: bool = False
    override_reason: str | None = None


class LiveLabMonitor:
    """Safe observational-only network monitor."""

    def __init__(
        self,
        engine: ReplayEngine | None = None,
        inference_service: Any | None = None,
        alert_threshold: float = 0.50,
        on_alert_callback: Callable[[AlertEvent], None] | None = None,
        on_flow_callback: Callable[[FlowObservation], None] | None = None,
        max_observations: int = 10000,
        dedup_window_s: float = 5.0,
        rule_engine: RuleEngine | None = None,
        policy: Any | None = None,
        safety_gate: Any | None = None,
        state_builder: Any | None = None,
        benchmark: str = "cicids2017",
    ) -> None:
        self.engine = engine
        self.inference_service = inference_service
        self.alert_threshold = alert_threshold
        self.on_alert_callback = on_alert_callback
        self.on_flow_callback = on_flow_callback
        self.max_observations = max_observations
        self.dedup_window_s = dedup_window_s
        self.rule_engine = rule_engine if rule_engine is not None else RuleEngine()
        self.policy = policy
        self.safety_gate = safety_gate
        self.state_builder = state_builder
        self.benchmark = benchmark
        self.alerts: list[AlertEvent] = []
        self.observations: deque[FlowObservation] = deque(maxlen=max_observations)
        self._last_alert_time: dict[str, float] = {}
        self._running = False

    def process_packet_stream(
        self,
        packet_generator: Generator[PacketInfo, None, None],
        ground_truth_resolver: Callable[[Flow], int | None] | None = None,
        mode: str = "live",
    ) -> list[AlertEvent]:
        """Ingest streaming packets in userland/test mode, evaluate flows, and emit alerts.

        Every completed flow produces a FlowObservation (streamed to
        ``on_flow_callback``); attack detections additionally produce an
        AlertEvent (streamed to ``on_alert_callback``).
        """
        idle_timeout = self.engine.idle_timeout_s if self.engine is not None else 120.0
        builder = FlowBuilder(idle_timeout_s=idle_timeout)
        self.alerts.clear()
        self._last_alert_time.clear()
        flow_idx = 0

        for pkt in packet_generator:
            completed = builder.process_packet(pkt)
            for fl in completed:
                flow_idx += 1
                self._evaluate_and_alert(fl, flow_idx, mode=mode)

        for fl in builder.flush_all():
            flow_idx += 1
            self._evaluate_and_alert(fl, flow_idx, mode=mode)

        return list(self.alerts)

    def _evaluate_and_alert(self, flow: Flow, flow_idx: int, mode: str = "live") -> None:
        """Run model inference, record the observation, and emit an alert when threshold is crossed."""
        features = flow.to_features()
        session_key = f"{flow.source_first_ip}->{flow.dest_first_ip}"
        rf_score = 0.0
        lstm_score: float | None = None
        fusion_score: float | None = None
        inf_source = "RF"

        if self.engine is not None and getattr(self.engine, "model", None) is not None and self.engine.model.__class__.__name__ != "RandomForestClassifier":
            # Custom or mock model supplied directly via engine
            pred, conf = self.engine.predict_features(features)
            rf_score = conf
            inf_source = "RF"
        elif self.inference_service is not None and hasattr(self.inference_service, "infer"):
            inf_res = self.inference_service.infer(
                features=features,
                session_key=session_key,
                benchmark=self.benchmark,
                threshold=self.alert_threshold,
            )
            pred = inf_res.prediction
            conf = float(inf_res.attack_score)
            rf_score = float(inf_res.rf_score)
            lstm_score = float(inf_res.lstm_score) if inf_res.lstm_score is not None else None
            fusion_score = float(inf_res.fusion_score) if inf_res.fusion_score is not None else None
            inf_source = "RF+LSTM_FUSION" if inf_res.inference_source == "RF+LSTM_FUSION" else "RF"
        elif self.engine is not None:
            pred, conf = self.engine.predict_features(features)
            rf_score = conf
            inf_source = "RF"
        else:
            raise RuntimeError("Neither inference_service nor engine is configured on LiveLabMonitor")

        proto = "TCP" if flow.key.protocol == 6 else ("UDP" if flow.key.protocol == 17 else f"PROTO_{flow.key.protocol}")

        # Deterministic rule checks (independent of ML model)
        rule_matches = self.rule_engine.evaluate_flow(flow)
        rule_ids = [r.rule_id for r in rule_matches]
        rule_alert = len(rule_matches) > 0
        model_alert = bool(pred == 1 and conf >= self.alert_threshold)
        is_alert = model_alert or rule_alert

        if model_alert and rule_alert:
            detection_source = "HYBRID"
        elif rule_alert:
            detection_source = "RULE"
        elif model_alert:
            detection_source = inf_source
        else:
            detection_source = "NONE"

        # Advisory DQN response policy and deterministic safety gate evaluation
        dqn_action_str: str | None = None
        enforced_action_str: str | None = None
        override_applied = False
        override_reason: str | None = None

        if self.state_builder is not None and self.policy is not None and self.safety_gate is not None:
            try:
                import torch
                from xrlids.response.types import Action
                bytes_per_s = features.get("flow_bytes_per_s", 0.0)
                state_vec = self.state_builder.build_state(attack_score=conf, flow_bytes_per_s=bytes_per_s)
                with torch.no_grad():
                    q_vals = self.policy(torch.from_numpy(state_vec).float().unsqueeze(0))
                    proposed_idx = int(torch.argmax(q_vals, dim=-1).item())
                    proposed_action = Action(proposed_idx)
                dqn_action_str = proposed_action.name

                enforced_action, override_applied, override_reason = self.safety_gate.enforce_safety(
                    step=flow_idx,
                    flow_id=f"live_{flow_idx}",
                    host_id=flow.source_first_ip,
                    proposed_action=proposed_action,
                )
                enforced_action_str = enforced_action.name
                rem_cool = self.safety_gate.get_remaining_cooldown(flow.source_first_ip, flow_idx)
                self.state_builder.update_history(
                    attack_score=conf,
                    enforced_action=enforced_action,
                    cooldown_remaining=rem_cool,
                )
            except Exception as exc:
                logger.debug("Policy/safety gate evaluation bypassed for flow %d: %s", flow_idx, exc)

        is_simulated = (mode == "sample")

        observation = FlowObservation(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow_idx,
            src_endpoint=f"{flow.source_first_ip}:{flow.source_first_port}",
            dst_endpoint=f"{flow.dest_first_ip}:{flow.dest_first_port}",
            protocol=proto,
            packet_count=flow.packet_count,
            duration_ms=round(flow.duration_ms, 2),
            attack_score=round(conf, 4),
            prediction_class=pred,
            prediction_label="ATTACK" if pred == 1 else "BENIGN",
            is_alert=is_alert,
            ground_truth="UNKNOWN",
            features=features,
            mode=mode,
            is_simulated=is_simulated,
            rule_triggered=rule_alert,
            rule_matches=rule_ids,
            detection_source=detection_source,
            rf_score=round(rf_score, 4) if rf_score is not None else None,
            lstm_score=round(lstm_score, 4) if lstm_score is not None else None,
            fusion_score=round(fusion_score, 4) if fusion_score is not None else None,
            dqn_action=dqn_action_str,
            enforced_action=enforced_action_str,
            safety_override=override_applied,
            override_reason=override_reason,
        )
        self.observations.append(observation)
        if self.on_flow_callback is not None:
            self.on_flow_callback(observation)

        if is_alert:
            has_high_rule = any(r.severity == "HIGH" for r in rule_matches)
            if conf >= 0.85 or has_high_rule:
                level = "HIGH"
            elif conf >= 0.65 or any(r.severity == "MEDIUM" for r in rule_matches):
                level = "MEDIUM"
            else:
                level = "LOW"

            alert_key = f"{observation.src_endpoint}->{observation.dst_endpoint}:{proto}"
            now_mono = time.monotonic()
            is_dedup = False
            if alert_key in self._last_alert_time:
                if (now_mono - self._last_alert_time[alert_key]) < self.dedup_window_s:
                    is_dedup = True

            if not is_dedup:
                self._last_alert_time[alert_key] = now_mono

            alert = AlertEvent(
                timestamp=observation.timestamp,
                flow_id=flow_idx,
                alert_level=level,
                confidence=round(conf, 4),
                src_endpoint=observation.src_endpoint,
                dst_endpoint=observation.dst_endpoint,
                protocol=proto,
                packet_count=flow.packet_count,
                duration_ms=round(flow.duration_ms, 2),
                details={k: round(v, 4) for k, v in features.items()},
                mode=mode,
                deduplicated=is_dedup,
                rule_triggered=rule_alert,
                rule_matches=rule_ids,
                detection_source=detection_source,
                rf_score=round(rf_score, 4) if rf_score is not None else None,
                lstm_score=round(lstm_score, 4) if lstm_score is not None else None,
                fusion_score=round(fusion_score, 4) if fusion_score is not None else None,
                dqn_action=dqn_action_str,
                enforced_action=enforced_action_str,
                safety_override=override_applied,
                override_reason=override_reason,
            )
            self.alerts.append(alert)
            if self.on_alert_callback is not None:
                self.on_alert_callback(alert)

    @classmethod
    def check_raw_socket_capability(cls) -> bool:
        """Check whether the current execution context has permissions for raw sockets."""
        try:
            # Attempt to create raw AF_PACKET socket (requires CAP_NET_RAW / root on Linux)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            return True
        except (PermissionError, OSError, AttributeError):
            return False
