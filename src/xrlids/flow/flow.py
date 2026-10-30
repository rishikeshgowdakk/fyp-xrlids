"""Bidirectional flow representation and feature calculation for XRL-IDARS (Phase 2).

Maintains flow lifecycle state, packet/byte accounting, directional statistics,
TCP flag observations, and computes:
1. R10 Features (10-dimensional vector for primary operational Random Forest).
2. R10-FlowSeq Features (11-dimensional vector with clamped binary flags and inter_flow_delta_s).

Strict Invariants:
- Preserves exact backwards compatibility with existing Random Forest checkpoints and tests.
- Separates RF 10-feature contract from LSTM 11-feature sequence contract.
- Population standard deviation (ddof=0) for packet length variance.
- Directionality preserved: forward = initiator (source_first_ip), backward = responder.
- Numerical safety: zero-duration rate protection, empty packet protection, finite clamping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import numpy as np

from xrlids.features.definitions import R10_FEATURES, R10_FLOWSEQ_FEATURES
from xrlids.flow.key import FlowKey

if TYPE_CHECKING:
    from xrlids.demo.pcap import PacketInfo


@dataclass
class Flow:
    """Aggregates packets belonging to a canonical bidirectional network flow."""

    key: FlowKey
    start_time: float
    last_time: float
    packet_lengths: list[int] = field(default_factory=list)
    total_bytes: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    is_closed: bool = False
    closed_reason: str | None = None
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
        """Accumulate packet into flow statistics and update lifecycle state."""
        if not self.packet_lengths:
            self.start_time = pkt.timestamp
            self.last_time = pkt.timestamp
            self.source_first_ip = pkt.src_ip
            self.source_first_port = pkt.src_port
            self.dest_first_ip = pkt.dst_ip
            self.dest_first_port = pkt.dst_port
        else:
            self.start_time = min(self.start_time, pkt.timestamp)
            self.last_time = max(self.last_time, pkt.timestamp)

        self.packet_lengths.append(pkt.packet_length)
        self.total_bytes += pkt.packet_length

        # Directional accounting: forward is defined by the connection initiator
        if pkt.src_ip == self.source_first_ip and pkt.src_port == self.source_first_port:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.packet_length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.packet_length

        # Protocol & flag accounting
        if pkt.is_tcp:
            if pkt.syn:
                self.syn_count += 1
            if pkt.ack:
                self.ack_count += 1
            if pkt.rst:
                self.rst_count += 1
                self.is_closed = True
                self.closed_reason = "rst"
            if pkt.fin:
                self.fin_count += 1
                self.is_closed = True
                self.closed_reason = "fin"
            if getattr(pkt, "psh", False):
                self.psh_count += 1
            if getattr(pkt, "urg", False):
                self.urg_count += 1

            # Anomaly / malformed flag combinations
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
        """Flow duration in seconds (>= 0.0)."""
        return max(0.0, self.last_time - self.start_time)

    @property
    def duration_ms(self) -> float:
        """Flow duration in milliseconds (>= 0.0)."""
        return self.duration_s * 1000.0

    @property
    def packet_count(self) -> int:
        """Total number of packets in the flow."""
        return len(self.packet_lengths)

    def to_features(self) -> dict[str, float]:
        """Compute the frozen 10-feature semantic contract (R10) for Random Forest.

        Maintains exact backward compatibility with existing RF checkpoints and tests.
        """
        dur_s = self.duration_s
        dur_s_eff = max(dur_s, 1e-6)
        dur_ms = self.duration_ms

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
        """Return 1D numpy array of shape (10,) ordered exactly by R10_FEATURES for RF."""
        feats = self.to_features()
        return np.array([feats[f] for f in R10_FEATURES], dtype=np.float32)

    def to_r10_flowseq_features(self, inter_flow_delta_s: float = 0.0) -> dict[str, float]:
        """Compute the canonical 11-feature R10-FlowSeq contract for temporal sequence processing.

        Key Invariants:
        - Clamps TCP flag counts to binary flow indicators in {0.0, 1.0} to prevent
          extreme out-of-distribution scaling anomalies (+121 sigma).
        - Clamps inter_flow_delta_s to [0.0, 300.0] seconds.
        - Uses population standard deviation (ddof=0).
        """
        dur_s = self.duration_s
        dur_s_eff = max(dur_s, 1e-6)
        dur_ms = self.duration_ms

        lengths = np.asarray(self.packet_lengths, dtype=float)
        mean_len = float(np.mean(lengths)) if len(lengths) > 0 else 0.0
        std_len = float(np.std(lengths)) if len(lengths) > 1 else 0.0

        packets_per_s = float(len(lengths) / dur_s_eff)
        bytes_per_s = float(self.total_bytes / dur_s_eff)

        # Clamped binary flow indicators matching offline Tuesday CSV Bernoulli distribution
        syn_clamped = min(float(self.syn_count), 1.0)
        ack_clamped = min(float(self.ack_count), 1.0)
        rst_clamped = min(float(self.rst_count), 1.0)
        fin_clamped = min(float(self.fin_count), 1.0)
        syn_ack_ratio = float(syn_clamped / max(ack_clamped, 1.0))

        # Clamped inter-flow delta
        delta_clamped = float(np.clip(float(inter_flow_delta_s), 0.0, 300.0))

        # Numerical safety sanitization
        def _safe(val: float, default: float = 0.0) -> float:
            if np.isnan(val) or np.isinf(val):
                return default
            return float(val)

        return {
            "flow_duration_ms": _safe(dur_ms, 0.0),
            "flow_packets_per_s": _safe(packets_per_s, 0.0),
            "flow_bytes_per_s": _safe(bytes_per_s, 0.0),
            "packet_length_mean": _safe(mean_len, 0.0),
            "packet_length_std": _safe(std_len, 0.0),
            "syn_count": syn_clamped,
            "ack_count": ack_clamped,
            "rst_count": rst_clamped,
            "fin_count": fin_clamped,
            "syn_ack_ratio": _safe(syn_ack_ratio, 0.0),
            "inter_flow_delta_s": delta_clamped,
        }

    def r10_flowseq_vector(self, inter_flow_delta_s: float = 0.0) -> np.ndarray:
        """Return 1D numpy array of shape (11,) ordered exactly by R10_FLOWSEQ_FEATURES."""
        feats = self.to_r10_flowseq_features(inter_flow_delta_s=inter_flow_delta_s)
        return np.array([feats[f] for f in R10_FLOWSEQ_FEATURES], dtype=np.float32)

    def to_dict(self) -> dict[str, Any]:
        """Return diagnostic summary dictionary."""
        return {
            "key": repr(self.key),
            "start_time": self.start_time,
            "last_time": self.last_time,
            "duration_ms": round(self.duration_ms, 2),
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "is_closed": self.is_closed,
            "closed_reason": self.closed_reason,
            "source_first_ip": self.source_first_ip,
            "source_first_port": self.source_first_port,
            "dest_first_ip": self.dest_first_ip,
            "dest_first_port": self.dest_first_port,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
        }
