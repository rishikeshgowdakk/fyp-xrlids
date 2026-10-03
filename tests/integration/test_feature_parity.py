"""Integration test: Strict numerical feature parity between offline formulas and live flow extraction (Task 5.2)."""

import numpy as np
import pandas as pd
import pytest

from xrlids.demo.extractor import verify_feature_parity
from xrlids.demo.flow import Flow, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES, feature_spec


def test_streaming_to_offline_r10_feature_parity():
    """Verify live flow accumulator features match offline canonical definitions within atol=1e-4."""
    # Define a deterministic multi-packet traffic sequence
    t_start = 1700000000.0
    packet_lengths = [64, 128, 1460, 512, 1460, 80, 1024, 64]
    delays = [0.0, 0.015, 0.035, 0.050, 0.080, 0.110, 0.150, 0.200]
    syn_flags = [1, 0, 0, 0, 0, 0, 0, 0]
    ack_flags = [1, 1, 1, 1, 1, 1, 1, 1]
    rst_flags = [0, 0, 0, 0, 0, 0, 0, 0]
    fin_flags = [0, 0, 0, 0, 0, 0, 0, 1]

    # 1. Accumulate via streaming Flow
    key = FlowKey("192.168.1.100", "10.0.0.5", 49500, 443, 6)
    flow = Flow(key=key, start_time=t_start, last_time=t_start)

    for i in range(len(packet_lengths)):
        ts = t_start + delays[i]
        pkt = PacketInfo(
            timestamp=ts,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            src_port=49500,
            dst_port=443,
            protocol=6,
            packet_length=packet_lengths[i],
            is_tcp=True,
            syn=bool(syn_flags[i]),
            ack=bool(ack_flags[i]),
            rst=bool(rst_flags[i]),
            fin=bool(fin_flags[i]),
        )
        flow.add_packet(pkt, is_forward=True)

    live_features = flow.to_features()

    # 2. Compute canonical offline features via src/xrlids/features/definitions.py
    duration_s = max(flow.duration_s, 1e-6)
    total_pkts = float(len(packet_lengths))
    total_bytes = float(sum(packet_lengths))

    sem_map = {
        "duration_seconds": pd.Series([duration_s]),
        "total_packets": pd.Series([total_pkts]),
        "total_bytes": pd.Series([total_bytes]),
        "pkt_len_mean": pd.Series([float(np.mean(packet_lengths))]),
        "pkt_len_std": pd.Series([float(np.std(packet_lengths))]),
        "syn_flags": pd.Series([float(sum(syn_flags))]),
        "ack_flags": pd.Series([float(sum(ack_flags))]),
        "rst_flags": pd.Series([float(sum(rst_flags))]),
        "fin_flags": pd.Series([float(sum(fin_flags))]),
    }

    offline_features: dict[str, float] = {}
    for feat_name in R10_FEATURES:
        spec = feature_spec(feat_name)
        val = float(spec.fn(sem_map).iloc[0])
        offline_features[feat_name] = val

    # 3. Verify feature parity within defined numerical tolerance (atol <= 1e-4)
    res = verify_feature_parity(offline_features, live_features, atol=1e-4)

    assert res["is_parity"] is True, f"Parity mismatch found: {res['mismatches']}"
    assert res["features_checked"] == 10
    assert res["max_delta"] <= 1e-4
    assert len(res["mismatches"]) == 0


def test_verify_feature_parity_detects_mismatch():
    """Verify that verify_feature_parity cleanly identifies discrepancies exceeding tolerance."""
    feat1 = {f: 1.0 for f in R10_FEATURES}
    feat2 = {f: 1.0 for f in R10_FEATURES}
    feat2["flow_packets_per_s"] = 1.005  # delta 0.005 > 1e-4

    res = verify_feature_parity(feat1, feat2, atol=1e-4)
    assert res["is_parity"] is False
    assert "flow_packets_per_s" in res["mismatches"]
    assert res["mismatches"]["flow_packets_per_s"]["abs_diff"] > 1e-4
