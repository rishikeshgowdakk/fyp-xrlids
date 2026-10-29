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
    detection_source: str = "RF"  # "RF", "RULE", "HYBRID"


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
    detection_source: str = "NONE"  # "RF", "RULE", "HYBRID", "NONE"


class LiveLabMonitor:
    """Safe observational-only network monitor."""

    def __init__(
        self,
        engine: ReplayEngine,
        alert_threshold: float = 0.50,
        on_alert_callback: Callable[[AlertEvent], None] | None = None,
        on_flow_callback: Callable[[FlowObservation], None] | None = None,
        max_observations: int = 10000,
        dedup_window_s: float = 5.0,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.engine = engine
        self.alert_threshold = alert_threshold
        self.on_alert_callback = on_alert_callback
        self.on_flow_callback = on_flow_callback
        self.max_observations = max_observations
        self.dedup_window_s = dedup_window_s
        self.rule_engine = rule_engine if rule_engine is not None else RuleEngine()
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
        builder = FlowBuilder(idle_timeout_s=self.engine.idle_timeout_s)
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
        pred, conf = self.engine.predict_features(features)
        proto = "TCP" if flow.key.protocol == 6 else ("UDP" if flow.key.protocol == 17 else f"PROTO_{flow.key.protocol}")

        # Deterministic rule checks (independent of ML model)
        rule_matches = self.rule_engine.evaluate_flow(flow)
        rule_ids = [r.rule_id for r in rule_matches]
        rule_alert = len(rule_matches) > 0
        rf_alert = bool(pred == 1 and conf >= self.alert_threshold)
        is_alert = rf_alert or rule_alert

        if rf_alert and rule_alert:
            detection_source = "HYBRID"
        elif rule_alert:
            detection_source = "RULE"
        elif rf_alert:
            detection_source = "RF"
        else:
            detection_source = "NONE"

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
