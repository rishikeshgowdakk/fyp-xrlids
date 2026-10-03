"""Bidirectional flow accumulator computing exact R10 semantic features.

Matches the flow aggregation contract of CICFlowMeter/R10:
- Bidirectional 5-tuple canonicalization: (ip1, ip2, port1, port2, protocol)
- 120.0s idle timeout or TCP FIN/RST completion
- Produces identical 10 semantic features:
  1. flow_duration_ms
  2. flow_packets_per_s
  3. flow_bytes_per_s
  4. packet_length_mean
  5. packet_length_std
  6. syn_count
  7. ack_count
  8. rst_count
  9. fin_count
  10. syn_ack_ratio
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generator, Sequence

import numpy as np

from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional flow key."""

    endpoint_a: str
    endpoint_b: str
    port_a: int
    port_b: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: PacketInfo) -> tuple[FlowKey, bool]:
        """Construct canonical FlowKey and return is_forward boolean."""
        ep1 = (pkt.src_ip, pkt.src_port)
        ep2 = (pkt.dst_ip, pkt.dst_port)
        if ep1 <= ep2:
            return cls(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol), True
        return cls(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol), False


@dataclass
class Flow:
    """Aggregates packets belonging to a bidirectional network flow."""

    key: FlowKey
    start_time: float
    last_time: float
    packet_lengths: list[int] = field(default_factory=list)
    total_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    is_closed: bool = False
    source_first_ip: str = ""
    source_first_port: int = 0
    dest_first_ip: str = ""
    dest_first_port: int = 0

    def add_packet(self, pkt: PacketInfo, is_forward: bool) -> None:
        """Accumulate packet into flow statistics."""
        if not self.packet_lengths:
            self.start_time = pkt.timestamp
            self.source_first_ip = pkt.src_ip
            self.source_first_port = pkt.src_port
            self.dest_first_ip = pkt.dst_ip
            self.dest_first_port = pkt.dst_port

        self.last_time = pkt.timestamp
        self.packet_lengths.append(pkt.packet_length)
        self.total_bytes += pkt.packet_length

        if pkt.is_tcp:
            if pkt.syn:
                self.syn_count += 1
            if pkt.ack:
                self.ack_count += 1
            if pkt.rst:
                self.rst_count += 1
                self.is_closed = True
            if pkt.fin:
                self.fin_count += 1
                self.is_closed = True

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def duration_ms(self) -> float:
        return self.duration_s * 1000.0

    @property
    def packet_count(self) -> int:
        return len(self.packet_lengths)

    def to_features(self) -> dict[str, float]:
        """Compute the frozen 10-feature semantic contract (R10)."""
        dur_s = self.duration_s
        dur_s_eff = max(dur_s, 1e-6)
        dur_ms = dur_s * 1000.0

        lengths = np.asarray(self.packet_lengths, dtype=float)
        mean_len = float(np.mean(lengths)) if len(lengths) > 0 else 0.0
        std_len = float(np.std(lengths)) if len(lengths) > 1 else 0.0

        packets_per_s = float(len(lengths) / dur_s_eff)
        bytes_per_s = float(self.total_bytes / dur_s_eff)
        syn_ack = float(self.syn_count / max(self.ack_count, 1.0))

        return {
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

    def feature_vector(self) -> np.ndarray:
        """Return 1D numpy array ordered exactly by R10_FEATURES."""
        feats = self.to_features()
        return np.array([feats[f] for f in R10_FEATURES], dtype=np.float32)


class FlowBuilder:
    """Manages active flows and yields completed flows based on timeout or FIN/RST."""

    def __init__(self, idle_timeout_s: float = 120.0) -> None:
        self.idle_timeout_s = idle_timeout_s
        self.active_flows: dict[FlowKey, Flow] = {}

    def process_packet(self, pkt: PacketInfo) -> list[Flow]:
        """Ingest a packet, expire timed-out flows, and return any completed flows."""
        completed: list[Flow] = []

        # Check expiration for other flows
        expired_keys = []
        for key, flow in self.active_flows.items():
            if pkt.timestamp - flow.last_time > self.idle_timeout_s:
                completed.append(flow)
                expired_keys.append(key)

        for k in expired_keys:
            del self.active_flows[k]

        key, is_fwd = FlowKey.from_packet(pkt)
        if key not in self.active_flows:
            flow = Flow(key=key, start_time=pkt.timestamp, last_time=pkt.timestamp)
            self.active_flows[key] = flow
        else:
            flow = self.active_flows[key]

        flow.add_packet(pkt, is_fwd)

        if flow.is_closed:
            completed.append(flow)
            del self.active_flows[key]

        return completed

    def flush_all(self) -> list[Flow]:
        """Flush all remaining active flows at the end of capture/replay."""
        flows = list(self.active_flows.values())
        self.active_flows.clear()
        return flows
