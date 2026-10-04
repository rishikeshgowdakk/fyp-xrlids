"""Automated Live Feature Parity Verification Harness (Phase 3C).

Compares streaming live/replay flow extraction against offline canonical
feature definitions across multiple controlled network traffic topologies.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.demo.flow import Flow, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES, feature_spec


@dataclass
class ParityResult:
    """Detailed numerical comparison result for an individual feature."""

    feature_name: str
    sample_count: int
    tolerance: float
    max_abs_error: float
    mean_abs_error: float
    max_rel_error: float
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "sample_count": self.sample_count,
            "tolerance": self.tolerance,
            "max_abs_error": round(self.max_abs_error, 6),
            "mean_abs_error": round(self.mean_abs_error, 6),
            "max_rel_error": round(self.max_rel_error, 6),
            "passed": self.passed,
        }


class LiveFeatureParityHarness:
    """Multi-sample verification harness for R10 live vs offline feature parity."""

    # Pre-registered numerical tolerances per feature
    TOLERANCES: dict[str, float] = {
        "flow_duration_ms": 1e-4,
        "flow_packets_per_s": 1e-3,
        "flow_bytes_per_s": 1e-3,
        "packet_length_mean": 1e-4,
        "packet_length_std": 1e-4,
        "syn_count": 0.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 1e-4,
    }

    @classmethod
    def generate_controlled_topologies(cls) -> list[list[PacketInfo]]:
        """Generate diverse multi-packet flow sequences representing distinct traffic patterns."""
        scenarios: list[list[PacketInfo]] = []

        # 1. Standard Interactive TCP (Handshake + Data + FIN Teardown)
        t0 = 1700000000.0
        tcp_flow = [
            # SYN
            PacketInfo(t0 + 0.000, "192.168.1.10", "10.0.0.1", 49152, 80, 6, 64, is_tcp=True, syn=True),
            # SYN-ACK
            PacketInfo(t0 + 0.010, "10.0.0.1", "192.168.1.10", 80, 49152, 6, 64, is_tcp=True, syn=True, ack=True),
            # ACK
            PacketInfo(t0 + 0.012, "192.168.1.10", "10.0.0.1", 49152, 80, 6, 54, is_tcp=True, ack=True),
            # HTTP Request
            PacketInfo(t0 + 0.020, "192.168.1.10", "10.0.0.1", 49152, 80, 6, 450, is_tcp=True, ack=True),
            # Response Chunk 1
            PacketInfo(t0 + 0.035, "10.0.0.1", "192.168.1.10", 80, 49152, 6, 1460, is_tcp=True, ack=True),
            # Response Chunk 2
            PacketInfo(t0 + 0.040, "10.0.0.1", "192.168.1.10", 80, 49152, 6, 1460, is_tcp=True, ack=True),
            # FIN
            PacketInfo(t0 + 0.060, "10.0.0.1", "192.168.1.10", 80, 49152, 6, 54, is_tcp=True, fin=True, ack=True),
        ]
        scenarios.append(tcp_flow)

        # 2. SYN Flood / Port Scan (Repeated SYNs, no ACKs, trailing RST)
        syn_burst = [
            PacketInfo(t0 + i * 0.002, "192.168.1.99", "10.0.0.5", 50000 + i, 443, 6, 64, is_tcp=True, syn=True)
            for i in range(15)
        ] + [
            PacketInfo(t0 + 0.035, "10.0.0.5", "192.168.1.99", 443, 50014, 6, 54, is_tcp=True, rst=True, ack=True)
        ]
        scenarios.append(syn_burst)

        # 3. Connectionless UDP Traffic (DNS Query and Response)
        udp_flow = [
            PacketInfo(t0 + 0.000, "192.168.1.20", "8.8.8.8", 53535, 53, 17, 72, is_tcp=False),
            PacketInfo(t0 + 0.015, "8.8.8.8", "192.168.1.20", 53, 53535, 17, 185, is_tcp=False),
        ]
        scenarios.append(udp_flow)

        # 4. Asymmetric Bulk Transfer (Many large data packets, periodic ACK)
        bulk_flow = []
        for i in range(20):
            bulk_flow.append(
                PacketInfo(t0 + i * 0.005, "10.0.0.2", "192.168.1.50", 443, 60000, 6, 1460, is_tcp=True, ack=True)
            )
            if i % 4 == 0:
                bulk_flow.append(
                    PacketInfo(t0 + i * 0.005 + 0.001, "192.168.1.50", "10.0.0.2", 60000, 443, 6, 64, is_tcp=True, ack=True)
                )
        scenarios.append(bulk_flow)

        # 5. Micro-Duration Flow (sub-millisecond duration)
        micro_flow = [
            PacketInfo(t0, "192.168.1.77", "10.0.0.1", 40000, 8080, 6, 128, is_tcp=True, syn=True),
            PacketInfo(t0 + 0.0001, "10.0.0.1", "192.168.1.77", 8080, 40000, 6, 128, is_tcp=True, rst=True),
        ]
        scenarios.append(micro_flow)

        return scenarios

    def evaluate_parity(self) -> dict[str, ParityResult]:
        """Execute feature parity check across all controlled scenarios."""
        scenarios = self.generate_controlled_topologies()
        results: dict[str, ParityResult] = {}

        # Collect live vs offline pairs across all scenarios
        live_rows: list[dict[str, float]] = []
        offline_rows: list[dict[str, float]] = []

        for pkt_list in scenarios:
            if not pkt_list:
                continue

            # 1. Compute via streaming Flow
            first = pkt_list[0]
            key = FlowKey(first.src_ip, first.dst_ip, first.src_port, first.dst_port, first.protocol)
            flow = Flow(key=key, start_time=first.timestamp, last_time=first.timestamp)
            for pkt in pkt_list:
                flow.add_packet(pkt, is_forward=(pkt.src_ip == first.src_ip))

            live_feats = flow.to_features()
            live_rows.append(live_feats)

            # 2. Compute canonical offline via definitions.py
            lengths = [p.packet_length for p in pkt_list]
            syn_flags = [1 if p.is_tcp and p.syn else 0 for p in pkt_list]
            ack_flags = [1 if p.is_tcp and p.ack else 0 for p in pkt_list]
            rst_flags = [1 if p.is_tcp and p.rst else 0 for p in pkt_list]
            fin_flags = [1 if p.is_tcp and p.fin else 0 for p in pkt_list]

            dur_s = flow.duration_s
            sem_map = {
                "duration_seconds": pd.Series([dur_s]),
                "total_packets": pd.Series([float(len(lengths))]),
                "total_bytes": pd.Series([float(sum(lengths))]),
                "pkt_len_mean": pd.Series([float(np.mean(lengths))]),
                "pkt_len_std": pd.Series([float(np.std(lengths)) if len(lengths) > 1 else 0.0]),
                "syn_flags": pd.Series([float(sum(syn_flags))]),
                "ack_flags": pd.Series([float(sum(ack_flags))]),
                "rst_flags": pd.Series([float(sum(rst_flags))]),
                "fin_flags": pd.Series([float(sum(fin_flags))]),
            }

            off_feats: dict[str, float] = {}
            for feat_name in R10_FEATURES:
                spec = feature_spec(feat_name)
                off_feats[feat_name] = float(spec.fn(sem_map).iloc[0])
            offline_rows.append(off_feats)

        df_live = pd.DataFrame(live_rows)
        df_off = pd.DataFrame(offline_rows)
        n_samples = len(scenarios)

        for feat in R10_FEATURES:
            v_live = df_live[feat].to_numpy()
            v_off = df_off[feat].to_numpy()
            abs_diffs = np.abs(v_live - v_off)
            max_abs = float(np.max(abs_diffs))
            mean_abs = float(np.mean(abs_diffs))

            non_zero = np.abs(v_off) > 1e-6
            if np.any(non_zero):
                rel_diffs = abs_diffs[non_zero] / np.abs(v_off[non_zero])
                max_rel = float(np.max(rel_diffs))
            else:
                max_rel = 0.0

            tol = self.TOLERANCES.get(feat, 1e-4)
            passed = bool(max_abs <= tol)

            results[feat] = ParityResult(
                feature_name=feat,
                sample_count=n_samples,
                tolerance=tol,
                max_abs_error=max_abs,
                mean_abs_error=mean_abs,
                max_rel_error=max_rel,
                passed=passed,
            )

        return results

    def to_dataframe(self) -> pd.DataFrame:
        """Return parity results formatted as a pandas DataFrame."""
        results = self.evaluate_parity()
        rows = [r.to_dict() for r in results.values()]
        return pd.DataFrame(rows)
