"""Canonical Flow Builder for XRL-IDARS (Phase 3).

Consolidates bidirectional network flow aggregation under Decision D-006:
- Bidirectional 5-tuple canonicalization: (ip1, ip2, port1, port2, protocol)
- Hybrid completion: TCP FIN/RST packet termination or 120.0s idle timeout
- Computes exact R10 semantic features with strict schema validation
- Preserves flow directionality, initiation endpoints, and TCP flag anomalies
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Sequence

import numpy as np

from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES
from xrlids.features.validator import FeatureSchemaValidator, FeatureValidationError
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class CanonicalFlowKey:
    """Canonical bidirectional 5-tuple flow key."""

    endpoint_a: str
    endpoint_b: str
    port_a: int
    port_b: int
    protocol: int

    @classmethod
    def from_endpoints(
        cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int
    ) -> tuple[CanonicalFlowKey, bool]:
        """Construct canonical FlowKey and return is_forward boolean.
        
        Orders endpoints deterministically so forward (A -> B) and reverse (B -> A)
        packets map to the identical CanonicalFlowKey.
        """
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            return cls(src_ip, dst_ip, src_port, dst_port, protocol), True
        return cls(dst_ip, src_ip, dst_port, src_port, protocol), False

    @classmethod
    def from_packet(cls, pkt: PacketInfo) -> tuple[CanonicalFlowKey, bool]:
        """Construct canonical FlowKey from PacketInfo."""
        return cls.from_endpoints(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )

    @property
    def flow_id(self) -> str:
        return f"{self.endpoint_a}:{self.port_a}<->{self.endpoint_b}:{self.port_b}/{self.protocol}"

    @property
    def src_ip(self) -> str:
        return self.endpoint_a

    @property
    def dst_ip(self) -> str:
        return self.endpoint_b

    @property
    def src_port(self) -> int:
        return self.port_a

    @property
    def dst_port(self) -> int:
        return self.port_b


@dataclass
class CanonicalFlow:
    """Aggregates packets belonging to a bidirectional network flow."""

    key: CanonicalFlowKey
    start_time: float
    last_time: float
    packet_lengths: list[int] = field(default_factory=list)
    packet_timestamps: list[float] = field(default_factory=list)
    total_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    is_closed: bool = False
    closed_reason: str = ""  # "FIN", "RST", "TIMEOUT", "FLUSH"
    source_first_ip: str = ""
    source_first_port: int = 0
    dest_first_ip: str = ""
    dest_first_port: int = 0
    invalid_flags_count: int = 0
    has_syn_fin: bool = False
    has_syn_rst: bool = False
    has_null_flags: bool = False
    has_xmas_flags: bool = False

    def add_packet(self, pkt: PacketInfo, is_forward: bool) -> None:
        """Accumulate packet into flow statistics and update TCP state."""
        if not self.packet_lengths:
            self.start_time = pkt.timestamp
            self.source_first_ip = pkt.src_ip
            self.source_first_port = pkt.src_port
            self.dest_first_ip = pkt.dst_ip
            self.dest_first_port = pkt.dst_port

        self.last_time = pkt.timestamp
        self.packet_lengths.append(pkt.packet_length)
        self.packet_timestamps.append(pkt.timestamp)
        self.total_bytes += pkt.packet_length

        if pkt.is_tcp:
            if pkt.syn:
                self.syn_count += 1
            if pkt.ack:
                self.ack_count += 1
            if pkt.rst:
                self.rst_count += 1
                self.is_closed = True
                self.closed_reason = "RST"
            if pkt.fin:
                self.fin_count += 1
                self.is_closed = True
                self.closed_reason = "FIN"
            if getattr(pkt, "psh", False):
                self.psh_count += 1
            if getattr(pkt, "urg", False):
                self.urg_count += 1

            # Check abnormal TCP flag combinations
            is_syn_fin = bool(pkt.syn and pkt.fin)
            is_syn_rst = bool(pkt.syn and pkt.rst)
            is_xmas = bool(pkt.fin and getattr(pkt, "psh", False) and getattr(pkt, "urg", False))
            raw_flags = getattr(pkt, "raw_flags", 0)
            is_null = bool(
                raw_flags == 0
                and not (
                    pkt.syn
                    or pkt.ack
                    or pkt.rst
                    or pkt.fin
                    or getattr(pkt, "psh", False)
                    or getattr(pkt, "urg", False)
                )
            )

            if is_syn_fin:
                self.has_syn_fin = True
                self.invalid_flags_count += 1
            if is_syn_rst:
                self.has_syn_rst = True
                self.invalid_flags_count += 1
            if is_xmas:
                self.has_xmas_flags = True
                self.invalid_flags_count += 1
            if is_null:
                self.has_null_flags = True
                self.invalid_flags_count += 1

    @property
    def duration_s(self) -> float:
        """Flow duration in seconds."""
        return max(0.0, self.last_time - self.start_time)

    @property
    def duration_ms(self) -> float:
        """Flow duration in milliseconds."""
        return self.duration_s * 1000.0

    @property
    def packet_count(self) -> int:
        """Total packet count across both directions."""
        return len(self.packet_lengths)

    def to_features(self, validate: bool = True) -> dict[str, float]:
        """Compute the canonical 10-feature contract (R10).
        
        Features:
        1. flow_duration_ms: Duration in milliseconds.
        2. flow_packets_per_s: Total packets / duration (sec).
        3. flow_bytes_per_s: Total bytes / duration (sec).
        4. packet_length_mean: Mean packet size in bytes.
        5. packet_length_std: Standard deviation of packet size in bytes.
        6. syn_count: TCP SYN flag count.
        7. ack_count: TCP ACK flag count.
        8. rst_count: TCP RST flag count.
        9. fin_count: TCP FIN flag count.
        10. syn_ack_ratio: syn_count / max(ack_count, 1.0).
        """
        dur_s = self.duration_s
        dur_s_eff = max(dur_s, 1e-6)
        dur_ms = dur_s * 1000.0

        lengths = np.asarray(self.packet_lengths, dtype=float)
        mean_len = float(np.mean(lengths)) if len(lengths) > 0 else 0.0
        std_len = float(np.std(lengths)) if len(lengths) > 1 else 0.0

        packets_per_s = float(len(lengths) / dur_s_eff)
        bytes_per_s = float(self.total_bytes / dur_s_eff)
        syn_ack = float(self.syn_count / max(self.ack_count, 1.0))

        features = {
            "flow_duration_ms": float(dur_ms),
            "flow_packets_per_s": float(packets_per_s),
            "flow_bytes_per_s": float(bytes_per_s),
            "packet_length_mean": float(mean_len),
            "packet_length_std": float(std_len),
            "syn_count": float(self.syn_count),
            "ack_count": float(self.ack_count),
            "rst_count": float(self.rst_count),
            "fin_count": float(self.fin_count),
            "syn_ack_ratio": float(syn_ack),
        }

        if validate:
            FeatureSchemaValidator("R10").validate(features)

        return features

    @property
    def features(self) -> dict[str, float]:
        """Convenience property returning extracted R10 features."""
        return self.to_features(validate=False)

    def to_feature_vector(self) -> np.ndarray:
        """Return canonical 1D float32 numpy array ordered strictly by R10_FEATURES."""
        feats = self.to_features(validate=True)
        return np.array([feats[f] for f in R10_FEATURES], dtype=np.float32)


@dataclass
class FlowBuilderStats:
    """Operational observability metrics for flow processing."""

    total_packets_processed: int = 0
    active_flows_count: int = 0
    flows_completed_fin_rst: int = 0
    flows_completed_timeout: int = 0
    flows_flushed: int = 0
    total_flows_completed: int = 0
    flow_builder_errors: int = 0
    max_active_flow_watermark: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_packets_processed": self.total_packets_processed,
            "active_flows_count": self.active_flows_count,
            "flows_completed_fin_rst": self.flows_completed_fin_rst,
            "flows_completed_timeout": self.flows_completed_timeout,
            "flows_flushed": self.flows_flushed,
            "total_flows_completed": self.total_flows_completed,
            "flow_builder_errors": self.flow_builder_errors,
            "max_active_flow_watermark": self.max_active_flow_watermark,
        }


class CanonicalFlowBuilder:
    """Canonical bidirectional flow accumulator enforcing Decision D-006.
    
    Manages active flow state machine, checks 120s timeout and TCP termination,
    and returns completed flows ready for inference and feature extraction.
    """

    def __init__(
        self,
        idle_timeout_s: float = 120.0,
        clock_mode: str = "packet",  # "packet" or "wall_clock"
    ) -> None:
        if clock_mode not in ("packet", "wall_clock"):
            raise ValueError(f"Invalid clock_mode '{clock_mode}', must be 'packet' or 'wall_clock'")
        self.idle_timeout_s = idle_timeout_s
        self.clock_mode = clock_mode
        self.active_flows: dict[CanonicalFlowKey, CanonicalFlow] = {}
        self.stats = FlowBuilderStats()

    def process_packet(self, pkt: PacketInfo) -> list[CanonicalFlow]:
        """Ingest a packet, expire timed-out flows, and return newly completed flows."""
        self.stats.total_packets_processed += 1
        current_time = time.monotonic() if self.clock_mode == "wall_clock" else pkt.timestamp
        completed: list[CanonicalFlow] = []

        # 1. Check expiration for existing flows (120s idle timeout fallback)
        expired_keys = []
        for key, flow in self.active_flows.items():
            ref_time = current_time if self.clock_mode == "wall_clock" else pkt.timestamp
            if ref_time - flow.last_time > self.idle_timeout_s:
                flow.is_closed = True
                flow.closed_reason = "TIMEOUT"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1

        for k in expired_keys:
            del self.active_flows[k]

        # 2. Map to canonical bidirectional 5-tuple
        try:
            key, is_fwd = CanonicalFlowKey.from_packet(pkt)
            if key not in self.active_flows:
                flow = CanonicalFlow(key=key, start_time=pkt.timestamp, last_time=pkt.timestamp)
                self.active_flows[key] = flow
            else:
                flow = self.active_flows[key]

            flow.add_packet(pkt, is_fwd)

            # 3. Check TCP FIN/RST completion
            if flow.is_closed:
                completed.append(flow)
                del self.active_flows[key]
                self.stats.flows_completed_fin_rst += 1
        except Exception as err:
            logger.error("Error processing packet in CanonicalFlowBuilder: %s", err)
            self.stats.flow_builder_errors += 1

        self.stats.active_flows_count = len(self.active_flows)
        self.stats.max_active_flow_watermark = max(
            self.stats.max_active_flow_watermark, self.stats.active_flows_count
        )
        self.stats.total_flows_completed += len(completed)
        return completed

    def check_timeouts(self, now: float | None = None) -> list[CanonicalFlow]:
        """Manually trigger timeout evaluation (e.g. periodically in live capture)."""
        current_time = (
            now
            if now is not None
            else (time.monotonic() if self.clock_mode == "wall_clock" else time.time())
        )
        completed: list[CanonicalFlow] = []
        expired_keys = []

        for key, flow in self.active_flows.items():
            if current_time - flow.last_time > self.idle_timeout_s:
                flow.is_closed = True
                flow.closed_reason = "TIMEOUT"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1

        for k in expired_keys:
            del self.active_flows[k]

        self.stats.active_flows_count = len(self.active_flows)
        self.stats.total_flows_completed += len(completed)
        return completed

    def flush_all(self) -> list[CanonicalFlow]:
        """Flush all remaining active flows at the conclusion of capture/replay."""
        flows = list(self.active_flows.values())
        for f in flows:
            f.is_closed = True
            f.closed_reason = "FLUSH"
        self.stats.flows_flushed += len(flows)
        self.stats.total_flows_completed += len(flows)
        self.active_flows.clear()
        self.stats.active_flows_count = 0
        return flows
