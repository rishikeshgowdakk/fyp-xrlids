"""Unit tests for the Canonical Flow Builder and processing layer."""

import numpy as np
import pytest

from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES
from xrlids.features.validator import FeatureValidationError
from xrlids.flow.canonical_builder import (
    CanonicalFlow,
    CanonicalFlowBuilder,
    CanonicalFlowKey,
    FlowBuilderStats,
)


def _make_pkt(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=12345,
    dst_port=80,
    protocol=6,
    length=100,
    ts=1000.0,
    syn=False,
    ack=False,
    rst=False,
    fin=False,
    psh=False,
    urg=False,
    raw_flags=0,
) -> PacketInfo:
    return PacketInfo(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=length,
        is_tcp=(protocol == 6),
        syn=syn,
        ack=ack,
        rst=rst,
        fin=fin,
        psh=psh,
        urg=urg,
        raw_flags=raw_flags,
    )


def test_canonical_flow_key_bidirectional():
    p1 = _make_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80)
    p2 = _make_pkt(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=1000)

    k1, is_fwd1 = CanonicalFlowKey.from_packet(p1)
    k2, is_fwd2 = CanonicalFlowKey.from_packet(p2)

    assert k1 == k2
    assert is_fwd1 is True
    assert is_fwd2 is False


def test_flow_packet_accumulation_and_features():
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)

    # Packet 1: SYN
    p1 = _make_pkt(ts=100.0, length=60, syn=True)
    res = builder.process_packet(p1)
    assert len(res) == 0

    # Packet 2: SYN-ACK (reverse)
    p2 = _make_pkt(src_ip="10.0.0.1", dst_ip="192.168.1.100", src_port=80, dst_port=12345, ts=100.05, length=60, syn=True, ack=True)
    res = builder.process_packet(p2)
    assert len(res) == 0

    # Packet 3: ACK + Data
    p3 = _make_pkt(ts=100.10, length=500, ack=True)
    res = builder.process_packet(p3)
    assert len(res) == 0

    # Packet 4: FIN
    p4 = _make_pkt(ts=100.20, length=60, fin=True, ack=True)
    res = builder.process_packet(p4)
    assert len(res) == 1

    flow = res[0]
    assert flow.is_closed is True
    assert flow.closed_reason == "FIN"
    assert flow.packet_count == 4
    assert flow.syn_count == 2
    assert flow.ack_count == 3
    assert flow.fin_count == 1
    assert flow.rst_count == 0

    feats = flow.to_features()
    assert feats["flow_duration_ms"] == pytest.approx(200.0)
    assert feats["syn_count"] == 2.0
    assert feats["ack_count"] == 3.0
    assert feats["syn_ack_ratio"] == pytest.approx(2.0 / 3.0)
    assert feats["packet_length_mean"] == pytest.approx((60 + 60 + 500 + 60) / 4.0)

    vec = flow.to_feature_vector()
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (10,)
    assert vec.dtype == np.float32


def test_flow_timeout_expiration():
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)

    p1 = _make_pkt(ts=100.0, syn=True)
    builder.process_packet(p1)
    assert len(builder.active_flows) == 1

    # Ingest packet for different session 125 seconds later
    p2 = _make_pkt(src_ip="10.0.0.99", dst_ip="10.0.0.1", src_port=9999, dst_port=80, ts=225.1)
    completed = builder.process_packet(p2)

    assert len(completed) == 1
    assert completed[0].key.port_a == 12345 or completed[0].key.port_b == 12345
    assert completed[0].closed_reason == "TIMEOUT"
    assert builder.stats.flows_completed_timeout == 1


def test_flow_rst_immediate_closure():
    builder = CanonicalFlowBuilder()
    p1 = _make_pkt(ts=50.0, syn=True)
    builder.process_packet(p1)

    p2 = _make_pkt(ts=50.01, rst=True)
    res = builder.process_packet(p2)

    assert len(res) == 1
    assert res[0].closed_reason == "RST"
    assert res[0].rst_count == 1
    assert len(builder.active_flows) == 0


def test_flow_anomalous_flags():
    builder = CanonicalFlowBuilder()

    # Xmas scan packet has FIN, so it closes immediately
    p_xmas = _make_pkt(ts=10.0, fin=True, psh=True, urg=True)
    res_xmas = builder.process_packet(p_xmas)
    assert len(res_xmas) == 1
    assert res_xmas[0].has_xmas_flags is True
    assert res_xmas[0].closed_reason == "FIN"

    # SYN-FIN packet also has FIN, so it closes immediately
    p_synfin = _make_pkt(src_ip="1.2.3.4", ts=10.1, syn=True, fin=True)
    res_synfin = builder.process_packet(p_synfin)
    assert len(res_synfin) == 1
    assert res_synfin[0].has_syn_fin is True

    # Established packets without termination flags stay active until flush
    p_active = _make_pkt(src_ip="2.2.2.2", ts=12.0, ack=True)
    res_act = builder.process_packet(p_active)
    assert len(res_act) == 0

    flows = builder.flush_all()
    assert len(flows) == 1
    assert flows[0].closed_reason == "FLUSH"
