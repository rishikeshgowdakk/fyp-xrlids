"""Observational-only live lab monitor for real-time intrusion alerting.

Strictly observational: monitors network interfaces or packet streams,
accumulates flows, runs model inference, and emits alerts.
NEVER mutates system firewall rules, routing tables, or iptables.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Generator

from xrlids.demo.flow import Flow, FlowBuilder
from xrlids.demo.pcap import PacketInfo, parse_packet_bytes
from xrlids.demo.replay import FlowPredictionEvent, ReplayEngine

logger = logging.getLogger(__name__)


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


class LiveLabMonitor:
    """Safe observational-only network monitor."""

    def __init__(
        self,
        engine: ReplayEngine,
        alert_threshold: float = 0.50,
        on_alert_callback: Callable[[AlertEvent], None] | None = None,
    ) -> None:
        self.engine = engine
        self.alert_threshold = alert_threshold
        self.on_alert_callback = on_alert_callback
        self.alerts: list[AlertEvent] = []
        self._running = False

    def process_packet_stream(
        self,
        packet_generator: Generator[PacketInfo, None, None],
        ground_truth_resolver: Callable[[Flow], int | None] | None = None,
    ) -> list[AlertEvent]:
        """Ingest streaming packets in userland/test mode, evaluate flows, and emit alerts."""
        builder = FlowBuilder(idle_timeout_s=self.engine.idle_timeout_s)
        self.alerts.clear()
        flow_idx = 0

        for pkt in packet_generator:
            completed = builder.process_packet(pkt)
            for fl in completed:
                flow_idx += 1
                self._evaluate_and_alert(fl, flow_idx)

        for fl in builder.flush_all():
            flow_idx += 1
            self._evaluate_and_alert(fl, flow_idx)

        return list(self.alerts)

    def _evaluate_and_alert(self, flow: Flow, flow_idx: int) -> None:
        """Run model inference and generate alert if probability exceeds threshold."""
        pred, conf = self.engine._predict_flow(flow)
        if pred == 1 and conf >= self.alert_threshold:
            proto = "TCP" if flow.key.protocol == 6 else ("UDP" if flow.key.protocol == 17 else f"PROTO_{flow.key.protocol}")
            level = "HIGH" if conf >= 0.85 else ("MEDIUM" if conf >= 0.65 else "LOW")
            alert = AlertEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow_idx,
                alert_level=level,
                confidence=round(conf, 4),
                src_endpoint=f"{flow.source_first_ip}:{flow.source_first_port}",
                dst_endpoint=f"{flow.dest_first_ip}:{flow.dest_first_port}",
                protocol=proto,
                packet_count=flow.packet_count,
                duration_ms=round(flow.duration_ms, 2),
                details={k: round(v, 4) for k, v in flow.to_features().items()},
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
