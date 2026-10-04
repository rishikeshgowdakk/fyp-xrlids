"""Unit tests for Phase 3B LiveFlowBuilder under Decision D-006."""

import pytest
import numpy as np

from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES
from xrlids.live.flow_builder import LiveFlowBuilder


def test_flow_builder_canonical_5tuple():
    """Verify bidirectional packets map to the identical FlowKey."""
    builder = LiveFlowBuilder()
    t0 = 1700000000.0

    # Forward packet
    pkt_fwd = PacketInfo(t0, "192.168.1.100", "10.0.0.5", 50000, 443, 6, 64, is_tcp=True)
    # Reverse packet
    pkt_rev = PacketInfo(t0 + 0.01, "10.0.0.5", "192.168.1.100", 443, 50000, 6, 64, is_tcp=True)

    completed = builder.process_packet(pkt_fwd)
    assert len(completed) == 0
    assert builder.stats.active_flows_count == 1

    completed = builder.process_packet(pkt_rev)
    assert len(completed) == 0
    # Both packets belonged to the exact same flow
    assert builder.stats.active_flows_count == 1

    flushed = builder.flush_all()
    assert len(flushed) == 1
    assert flushed[0].packet_count == 2


def test_flow_builder_d006_fin_completion():
    """Verify TCP FIN terminates active flow tracking immediately per D-006."""
    builder = LiveFlowBuilder()
    t0 = 1700000000.0

    pkt1 = PacketInfo(t0, "192.168.1.10", "10.0.0.1", 4000, 80, 6, 64, is_tcp=True, syn=True)
    pkt2 = PacketInfo(t0 + 0.01, "10.0.0.1", "192.168.1.10", 80, 4000, 6, 64, is_tcp=True, ack=True)
    pkt3 = PacketInfo(t0 + 0.02, "192.168.1.10", "10.0.0.1", 4000, 80, 6, 64, is_tcp=True, fin=True, ack=True)

    assert len(builder.process_packet(pkt1)) == 0
    assert len(builder.process_packet(pkt2)) == 0
    completed = builder.process_packet(pkt3)

    assert len(completed) == 1
    assert completed[0].fin_count == 1
    assert completed[0].packet_count == 3
    assert builder.stats.flows_completed_fin_rst == 1
    assert builder.stats.active_flows_count == 0


def test_flow_builder_d006_rst_completion():
    """Verify TCP RST terminates active flow tracking immediately per D-006."""
    builder = LiveFlowBuilder()
    t0 = 1700000000.0

    pkt1 = PacketInfo(t0, "192.168.1.10", "10.0.0.1", 4001, 80, 6, 64, is_tcp=True, syn=True)
    pkt2 = PacketInfo(t0 + 0.01, "10.0.0.1", "192.168.1.10", 80, 4001, 6, 64, is_tcp=True, rst=True)

    assert len(builder.process_packet(pkt1)) == 0
    completed = builder.process_packet(pkt2)

    assert len(completed) == 1
    assert completed[0].rst_count == 1
    assert builder.stats.flows_completed_fin_rst == 1


def test_flow_builder_d006_idle_timeout():
    """Verify 120s idle timeout fallback marks inactive flows completed per D-006."""
    builder = LiveFlowBuilder(idle_timeout_s=120.0)
    t0 = 1700000000.0

    # Flow A packet
    pkt_a1 = PacketInfo(t0, "10.0.0.1", "10.0.0.2", 1111, 2222, 17, 100, is_tcp=False)
    # Flow B packet arrives 130s later (Flow A has been idle > 120s)
    pkt_b1 = PacketInfo(t0 + 130.0, "10.0.0.3", "10.0.0.4", 3333, 4444, 17, 100, is_tcp=False)

    assert len(builder.process_packet(pkt_a1)) == 0
    completed = builder.process_packet(pkt_b1)

    assert len(completed) == 1
    assert completed[0].key.port_a in (1111, 2222)
    assert builder.stats.flows_completed_timeout == 1
    assert builder.stats.active_flows_count == 1  # Flow B is active


def test_flow_r10_feature_vector_contract():
    """Verify computed flow features adhere to the frozen R10 contract."""
    builder = LiveFlowBuilder()
    t0 = 1700000000.0

    pkt = PacketInfo(t0, "192.168.1.5", "10.0.0.10", 5000, 80, 6, 128, is_tcp=True, syn=True)
    builder.process_packet(pkt)
    flow = builder.flush_all()[0]

    feats = flow.to_features()
    vec = flow.feature_vector()

    assert len(feats) == len(R10_FEATURES)
    assert set(feats.keys()) == set(R10_FEATURES)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (10,)
    assert vec.dtype == np.float32
