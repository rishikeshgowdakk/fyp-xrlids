"""Unit tests for bidirectional flow accumulation and R10 feature calculation."""

import numpy as np

from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES


def test_flow_key_bidirectional_canonicalization():
    """Ensure packets in opposite directions map to the identical canonical FlowKey."""
    p_fwd = PacketInfo(
        timestamp=1.0,
        src_ip="192.168.1.5",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=80,
        protocol=6,
        packet_length=64,
        is_tcp=True,
    )
    p_bwd = PacketInfo(
        timestamp=1.1,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.5",
        src_port=80,
        dst_port=50000,
        protocol=6,
        packet_length=128,
        is_tcp=True,
    )

    k_fwd, is_fwd1 = FlowKey.from_packet(p_fwd)
    k_bwd, is_fwd2 = FlowKey.from_packet(p_bwd)

    assert k_fwd == k_bwd
    assert is_fwd1 != is_fwd2


def test_flow_r10_features_exactness():
    """Verify that Flow.to_features() computes the exact frozen 10 R10 features."""
    key = FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    fl = Flow(key=key, start_time=100.0, last_time=100.0)

    # 4 packets: 100 bytes, 200 bytes, 300 bytes, 400 bytes over 0.5s
    # Flags: 2 SYN, 4 ACK, 0 RST, 0 FIN
    times = [100.0, 100.1, 100.3, 100.5]
    lengths = [100, 200, 300, 400]
    syns = [True, True, False, False]
    acks = [True, True, True, True]

    for t, l, s, a in zip(times, lengths, syns, acks):
        pkt = PacketInfo(
            timestamp=t,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=6,
            packet_length=l,
            is_tcp=True,
            syn=s,
            ack=a,
        )
        fl.add_packet(pkt, is_forward=True)

    feats = fl.to_features()
    assert set(feats.keys()) == set(R10_FEATURES)

    # Duration = 0.5s = 500 ms
    assert abs(feats["flow_duration_ms"] - 500.0) < 1e-5
    # Total packets = 4, dur = 0.5s -> 8.0 packets/s
    assert abs(feats["flow_packets_per_s"] - 8.0) < 1e-4
    # Total bytes = 1000, dur = 0.5s -> 2000.0 bytes/s
    assert abs(feats["flow_bytes_per_s"] - 2000.0) < 1e-4
    # Mean length = 250.0
    assert abs(feats["packet_length_mean"] - 250.0) < 1e-5
    # Std length = std([100, 200, 300, 400])
    expected_std = float(np.std([100, 200, 300, 400]))
    assert abs(feats["packet_length_std"] - expected_std) < 1e-4
    # Flags
    assert feats["syn_count"] == 2.0
    assert feats["ack_count"] == 4.0
    assert feats["rst_count"] == 0.0
    assert feats["fin_count"] == 0.0
    assert abs(feats["syn_ack_ratio"] - 0.5) < 1e-5


def test_flow_builder_fin_and_rst_termination():
    """Verify D-006 policy: TCP FIN or RST closes and emits the flow immediately."""
    builder = FlowBuilder(idle_timeout_s=120.0)

    # Packet 1: SYN
    p1 = PacketInfo(1.0, "10.0.0.1", "10.0.0.2", 1000, 80, 6, 64, True, syn=True)
    out1 = builder.process_packet(p1)
    assert len(out1) == 0
    assert len(builder.active_flows) == 1

    # Packet 2: FIN -> terminates flow
    p2 = PacketInfo(1.1, "10.0.0.2", "10.0.0.1", 80, 1000, 6, 64, True, fin=True, ack=True)
    out2 = builder.process_packet(p2)
    assert len(out2) == 1
    assert len(builder.active_flows) == 0
    assert out2[0].fin_count == 1


def test_flow_builder_idle_timeout_expiration():
    """Verify D-006 policy: 120s idle timeout triggers flow completion."""
    builder = FlowBuilder(idle_timeout_s=120.0)

    p1 = PacketInfo(10.0, "10.0.0.1", "10.0.0.2", 2000, 53, 17, 64, False)
    builder.process_packet(p1)
    assert len(builder.active_flows) == 1

    # Packet for a new flow arriving at t = 135.0 (> 120s later)
    p2 = PacketInfo(135.0, "10.0.0.5", "10.0.0.6", 3000, 80, 6, 64, True)
    out = builder.process_packet(p2)
    assert len(out) == 1
    assert out[0].key.port_a == 2000 or out[0].key.port_b == 2000
    assert len(builder.active_flows) == 1


def test_flow_builder_flush_all():
    """Verify flush_all yields all active flows and clears tracking state."""
    builder = FlowBuilder(idle_timeout_s=120.0)
    p1 = PacketInfo(1.0, "1.1.1.1", "2.2.2.2", 100, 200, 6, 64, True)
    p2 = PacketInfo(2.0, "3.3.3.3", "4.4.4.4", 300, 400, 17, 64, False)

    builder.process_packet(p1)
    builder.process_packet(p2)
    assert len(builder.active_flows) == 2

    flushed = builder.flush_all()
    assert len(flushed) == 2
    assert len(builder.active_flows) == 0
