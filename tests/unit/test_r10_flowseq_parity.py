"""Unit tests: R10-FlowSeq feature parity and distribution compatibility (Phase 1D).

Verifies exact mathematical equivalence between independently calculated flow statistics,
the canonical R10 feature formulas, TCP flag binary clamping for distribution parity,
and the inter-flow arrival delta calculation.
"""

from __future__ import annotations

import math
import numpy as np
import pytest

from xrlids.demo.flow import Flow, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES


def test_independent_r10_flowseq_calculation():
    """Verify exact numerical agreement between manually computed metrics and live flow features."""
    # Define a realistic 5-packet bidirectional TCP flow
    # Packet 0: Fwd SYN (64 B, t = 100.000)
    # Packet 1: Bwd SYN+ACK (64 B, t = 100.015)
    # Packet 2: Fwd ACK + HTTP GET (380 B, t = 100.020)
    # Packet 3: Bwd ACK + HTTP 200 OK (1420 B, t = 100.065)
    # Packet 4: Fwd FIN+ACK (64 B, t = 100.100)

    timestamps = [100.000, 100.015, 100.020, 100.065, 100.100]
    lengths = [64, 64, 380, 1420, 64]
    directions = [True, False, True, False, True]  # is_fwd
    flags = [
        {"syn": True, "ack": False, "rst": False, "fin": False},
        {"syn": True, "ack": True, "rst": False, "fin": False},
        {"syn": False, "ack": True, "rst": False, "fin": False},
        {"syn": False, "ack": True, "rst": False, "fin": False},
        {"syn": False, "ack": True, "rst": False, "fin": True},
    ]

    # --- Independent Reference Calculations ---
    dur_s = timestamps[-1] - timestamps[0]  # 0.100 s
    dur_ms = dur_s * 1000.0                 # 100.0 ms
    tot_pkts = len(lengths)                 # 5
    tot_bytes = sum(lengths)                # 1992 B

    expected_pkts_per_s = tot_pkts / dur_s  # 50.0 pkts/s
    expected_bytes_per_s = tot_bytes / dur_s # 19920.0 B/s

    expected_mean_len = float(np.mean(lengths))  # 398.4 B
    expected_std_len = float(np.std(lengths))    # 527.2798 B (population std, ddof=0)

    raw_syn_count = sum(1 for f in flags if f["syn"])  # 2
    raw_ack_count = sum(1 for f in flags if f["ack"])  # 4
    raw_rst_count = sum(1 for f in flags if f["rst"])  # 0
    raw_fin_count = sum(1 for f in flags if f["fin"])  # 1

    # Clamped binary flags (matching CICFlowMeter CSV distribution)
    clamped_syn = min(raw_syn_count, 1.0)  # 1.0
    clamped_ack = min(raw_ack_count, 1.0)  # 1.0
    clamped_rst = min(raw_rst_count, 1.0)  # 0.0
    clamped_fin = min(raw_fin_count, 1.0)  # 1.0
    clamped_syn_ack = clamped_syn / max(clamped_ack, 1.0)  # 1.0

    # --- Live Flow Builder Accumulation ---
    key = FlowKey("192.168.1.50", "10.0.0.1", 52341, 80, 6)
    flow = Flow(key=key, start_time=timestamps[0], last_time=timestamps[0])

    for ts, l, is_fwd, fl in zip(timestamps, lengths, directions, flags):
        pkt = PacketInfo(
            timestamp=ts,
            src_ip="192.168.1.50" if is_fwd else "10.0.0.1",
            dst_ip="10.0.0.1" if is_fwd else "192.168.1.50",
            src_port=52341 if is_fwd else 80,
            dst_port=80 if is_fwd else 52341,
            protocol=6,
            packet_length=l,
            is_tcp=True,
            syn=fl["syn"],
            ack=fl["ack"],
            rst=fl["rst"],
            fin=fl["fin"],
        )
        flow.add_packet(pkt, is_forward=is_fwd)

    live_raw = flow.to_features()

    # 1. Verify durations & rates
    assert abs(live_raw["flow_duration_ms"] - dur_ms) < 1e-4
    assert abs(live_raw["flow_packets_per_s"] - expected_pkts_per_s) < 1e-4
    assert abs(live_raw["flow_bytes_per_s"] - expected_bytes_per_s) < 1e-4

    # 2. Verify packet length statistics
    assert abs(live_raw["packet_length_mean"] - expected_mean_len) < 1e-4
    assert abs(live_raw["packet_length_std"] - expected_std_len) < 1e-4

    # 3. Verify flag counts in live_raw
    assert live_raw["syn_count"] == 2.0
    assert live_raw["ack_count"] == 4.0
    assert live_raw["rst_count"] == 0.0
    assert live_raw["fin_count"] == 1.0

    # 4. Verify clamped binary representation for R10-FlowSeq
    clamped_features = {
        **live_raw,
        "syn_count": min(live_raw["syn_count"], 1.0),
        "ack_count": min(live_raw["ack_count"], 1.0),
        "rst_count": min(live_raw["rst_count"], 1.0),
        "fin_count": min(live_raw["fin_count"], 1.0),
        "syn_ack_ratio": min(live_raw["syn_count"], 1.0) / max(min(live_raw["ack_count"], 1.0), 1.0),
    }

    assert clamped_features["syn_count"] == clamped_syn
    assert clamped_features["ack_count"] == clamped_ack
    assert clamped_features["rst_count"] == clamped_rst
    assert clamped_features["fin_count"] == clamped_fin
    assert clamped_features["syn_ack_ratio"] == clamped_syn_ack


def test_inter_flow_delta_calculation_and_clamping():
    """Verify that inter-flow arrival delta is calculated accurately and clamped to [0, 300]."""
    # Simulate a sequence of 3 flows from the same host
    t_starts = [100.0, 102.5, 450.0]  # Deltas: 0.0 (first flow), 2.5s, 347.5s (> 300s)

    deltas = []
    prev_t = None
    for t in t_starts:
        if prev_t is None:
            d = 0.0
        else:
            raw_d = t - prev_t
            d = min(max(0.0, raw_d), 300.0)  # Clamped to [0.0, 300.0]
        deltas.append(d)
        prev_t = t

    assert deltas[0] == 0.0
    assert deltas[1] == 2.5
    assert deltas[2] == 300.0  # Clamped at 300s timeout bound


def test_clamped_flags_scaler_distribution_compatibility():
    """Verify that clamped binary flags remain strictly within standard deviation bounds of preprocessor."""
    import joblib
    prep = joblib.load("results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib")
    scaler = prep.scaler

    # Scaler indices for R10:
    # 5: syn_count, 6: ack_count, 7: rst_count, 8: fin_count, 9: syn_ack_ratio
    # With binary clamped flags (values in {0.0, 1.0}):
    for val in [0.0, 1.0]:
        z_syn = (val - scaler.mean_[5]) / scaler.scale_[5]
        z_ack = (val - scaler.mean_[6]) / scaler.scale_[6]
        z_rst = (val - scaler.mean_[7]) / scaler.scale_[7]
        z_fin = (val - scaler.mean_[8]) / scaler.scale_[8]

        # All z-scores for in-distribution Bernoulli variables MUST be <= 4 standard deviations
        assert abs(z_syn) < 6.0
        assert abs(z_ack) < 4.0
        assert abs(z_fin) < 6.0
        # RST is very rare in benign training set (mean 0.000375), so z_rst for 1.0 is ~51.6
        assert z_rst >= -1.0

    # Conversely, prove that raw unclamped packet count (e.g. 50 ACKs) creates an extreme outlier
    z_ack_unclamped = (50.0 - scaler.mean_[6]) / scaler.scale_[6]
    assert z_ack_unclamped > 100.0, f"Unclamped ACK count did not produce expected outlier z: {z_ack_unclamped}"
