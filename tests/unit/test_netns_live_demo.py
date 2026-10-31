"""Unit and integration tests for Real Netns Live Demo & ICMP Ping Ingestion."""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import pytest

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.capture.netns_capture_worker import parse_packet_bytes
from xrlids.capture.netns_ipc import NetnsPacketReceiver
from xrlids.demo.pcap import PacketInfo
from xrlids.demo.privileged_runner import privileged_netns_cmd_runner
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.response.firewall import LabFirewallManager
from xrlids.response.types import Action


# ---------------------------------------------------------------------------
# 1. Flow Builder ICMP Prompt Expiration vs TCP Timeout
# ---------------------------------------------------------------------------
def test_flow_builder_icmp_prompt_timeout():
    """Verify that ICMP flows expire after 2.0s idle, while TCP flows wait 120s."""
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0, icmp_idle_timeout_s=2.0)

    t0 = 1000.0
    # Add ICMP packet
    pkt_icmp = PacketInfo(
        timestamp=t0,
        packet_length=84,
        src_ip="10.200.1.2",
        dst_ip="10.200.1.3",
        src_port=0,
        dst_port=0,
        protocol=1,
        is_tcp=False,
    )
    completed = builder.process_packet(pkt_icmp)
    assert len(completed) == 0
    assert len(builder.active_flows) == 1

    # Check timeout after 1.5s -> Should NOT expire yet
    expired_early = builder.check_timeouts(now=t0 + 1.5)
    assert len(expired_early) == 0
    assert len(builder.active_flows) == 1

    # Check timeout after 2.1s -> ICMP flow MUST expire promptly
    expired_on_time = builder.check_timeouts(now=t0 + 2.1)
    assert len(expired_on_time) == 1
    assert expired_on_time[0].protocol == 1
    assert len(builder.active_flows) == 0


def test_flow_builder_tcp_preserves_long_timeout():
    """Verify that TCP flows still use the 120s timeout and do not expire at 2.0s."""
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0, icmp_idle_timeout_s=2.0)

    t0 = 1000.0
    pkt_tcp = PacketInfo(
        timestamp=t0,
        packet_length=100,
        src_ip="10.200.1.2",
        dst_ip="10.200.1.3",
        src_port=44556,
        dst_port=80,
        protocol=6,
        is_tcp=True,
    )
    builder.process_packet(pkt_tcp)
    assert len(builder.active_flows) == 1

    # Check timeout after 5.0s -> TCP flow should NOT expire
    expired_5s = builder.check_timeouts(now=t0 + 5.0)
    assert len(expired_5s) == 0
    assert len(builder.active_flows) == 1

    # Check timeout after 125.0s -> TCP flow should expire
    expired_125s = builder.check_timeouts(now=t0 + 125.0)
    assert len(expired_125s) == 1
    assert expired_125s[0].protocol == 6
    assert len(builder.active_flows) == 0


# ---------------------------------------------------------------------------
# 2. Raw Ethernet Frame Parsing in netns_capture_worker
# ---------------------------------------------------------------------------
def _build_raw_icmp_frame(src_ip="10.200.1.2", dst_ip="10.200.1.3") -> bytes:
    """Build a synthetic raw Ethernet + IPv4 + ICMP Echo Request frame."""
    # Ethernet header: dst MAC (6) + src MAC (6) + EtherType 0x0800 (IPv4)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    # IPv4 header: ver/ihl=0x45, tos=0, total_len=84, id=1, flags/frag=0, ttl=64, proto=1 (ICMP), chksum=0, src, dst
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 84, 1, 0, 64, 1, 0, src_bytes, dst_bytes)

    # ICMP echo request: type=8, code=0, chksum=0, id=123, seq=1 + 56 bytes payload
    icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, 123, 1)
    payload = b"X" * 56
    return eth_hdr + ip_hdr + icmp_hdr + payload


def test_parse_packet_bytes_icmp():
    """Verify raw Ethernet frame parsing into canonical PacketInfo for ICMP."""
    frame = _build_raw_icmp_frame()
    pkt = parse_packet_bytes(frame, timestamp=1700000000.0)

    assert pkt is not None
    assert pkt.src_ip == "10.200.1.2"
    assert pkt.dst_ip == "10.200.1.3"
    assert pkt.protocol == 1
    assert not pkt.is_tcp
    assert pkt.packet_length == 84


def test_parse_packet_bytes_ignores_non_ipv4():
    """Verify that ARP or non-IPv4 frames are safely filtered out."""
    # EtherType 0x0806 is ARP
    arp_frame = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x06" + b"\x00" * 40
    pkt = parse_packet_bytes(arp_frame, timestamp=1700000000.0)
    assert pkt is None


# ---------------------------------------------------------------------------
# 3. Unix Domain Socket IPC Serialization & Deserialization
# ---------------------------------------------------------------------------
def test_netns_ipc_receiver_stream(tmp_path):
    """Verify Unix domain socket IPC receiver accepts client connection and deserializes packets."""
    sock_path = str(tmp_path / "test_ipc.sock")
    receiver = NetnsPacketReceiver(socket_path=sock_path)

    ok, msg = receiver.start()
    assert ok
    assert os.path.exists(sock_path)

    # Simulate client connection (like netns_capture_worker)
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(sock_path)

    # Handshake
    client_sock.sendall(json.dumps({"type": "WORKER_READY"}).encode("utf-8") + b"\n")

    # Send 3 packet objects
    p1 = {
        "timestamp": 1000.1,
        "packet_length": 84,
        "src_ip": "10.200.1.2",
        "dst_ip": "10.200.1.3",
        "src_port": 0,
        "dst_port": 0,
        "protocol": 1,
        "is_tcp": False,
    }
    p2 = {
        "timestamp": 1000.2,
        "packet_length": 84,
        "src_ip": "10.200.1.2",
        "dst_ip": "10.200.1.3",
        "src_port": 0,
        "dst_port": 0,
        "protocol": 1,
        "is_tcp": False,
    }
    client_sock.sendall(json.dumps(p1).encode("utf-8") + b"\n")
    client_sock.sendall(json.dumps(p2).encode("utf-8") + b"\n")
    client_sock.close()

    # Read from receiver
    r1 = receiver.get_packet(timeout=1.0)
    r2 = receiver.get_packet(timeout=1.0)
    assert r1 is not None
    assert r1.protocol == 1
    assert r1.src_ip == "10.200.1.2"
    assert r2 is not None

    stats = receiver.get_stats()
    assert stats["packets_captured"] == 2
    assert stats["icmp_packets"] == 2
    assert stats["bytes_captured"] == 168

    receiver.stop()
    assert not os.path.exists(sock_path)


# ---------------------------------------------------------------------------
# 4. End-to-End ICMP Flood Pipeline Processing & Honest Attribution
# ---------------------------------------------------------------------------
def test_icmp_flood_end_to_end_pipeline(tmp_path):
    """Verify that an ICMP burst is processed end-to-end through ActiveInferencePipeline.

    Checks:
    - Flow assembly with R10 features.
    - Honest RF classifier (preserves true ML output, does not fake ATTACK).
    - Rule Engine matches RULE-ICMP-FLOOD.
    - Hybrid Arbiter resolves verdict to RULE.
    - DQN evaluates 6D state and proposes an action.
    - Event provenance is tagged 'REAL LIVE CAPTURE'.
    """
    event_mgr = EventManager(audit_log_path=tmp_path / "events.jsonl")
    pipeline = ActiveInferencePipeline(event_manager=event_mgr, explain_all=True)

    builder = CanonicalFlowBuilder(idle_timeout_s=120.0, icmp_idle_timeout_s=2.0)

    # Generate 100 rapid ICMP echo request packets (simulating flood burst)
    t_start = 1000.0
    for i in range(100):
        pkt = PacketInfo(
            timestamp=t_start + (i * 0.01),
            packet_length=84,
            src_ip="10.200.1.2",
            dst_ip="10.200.1.3",
            src_port=0,
            dst_port=0,
            protocol=1,
            is_tcp=False,
        )
        builder.process_packet(pkt)

    # Prompt timeout after 2.1s idle
    flows = builder.check_timeouts(now=t_start + 1.0 + 2.1)
    assert len(flows) == 1
    flow = flows[0]

    # Process flow through canonical active pipeline
    res = pipeline.process_flow(flow, source_mode="REAL LIVE CAPTURE")

    # Assertions
    assert res.source_mode == "REAL LIVE CAPTURE"
    assert res.protocol == 1
    assert flow.packet_count == 100
    assert res.features["packet_length_mean"] == 84.0
    assert res.features["syn_count"] == 0

    # Rule Engine MUST catch the ICMP flood violation
    rule_ids = [r.rule_id for r in res.rule_matches]
    assert "RULE-ICMP-FLOOD" in rule_ids

    # Hybrid Decision must reflect Rule Engine match
    assert res.hybrid.detection_source == "RULE"
    assert res.hybrid.is_attack is True
    assert res.security_event.hybrid_verdict in ("RULE", "HYBRID")

    # RF ML classifier output is honest and distinct from rule detection
    assert isinstance(res.inference.attack_score, float)
    # The RF was trained on CIC-IDS2017 features where 84-byte ping packets have low anomaly scores.
    # We assert that the system does NOT overwrite this with a fabricated 0.99 score.
    assert res.inference.attack_score < 0.50

    # DQN response recommendation
    assert res.response.action in (Action.ISOLATE, Action.RATE_LIMIT, Action.ALERT)
    assert res.enforced_action in (Action.ISOLATE, Action.RATE_LIMIT, Action.ALERT)
    assert len(res.response.state_vector) == 6
    assert len(res.response.q_values) == 4

    # TreeSHAP explanation generated
    assert res.explanation is not None
    assert len(res.explanation.attributions) > 0

    # Security event recorded
    recent = event_mgr.get_recent_events(limit=5)
    assert len(recent) >= 1
    latest = recent[0]
    assert latest.source_mode == "REAL LIVE CAPTURE"
    assert latest.source_ip == "10.200.1.2"
    assert latest.dest_ip == "10.200.1.3"


# ---------------------------------------------------------------------------
# 5. Privileged Runner & Netns Command Runner
# ---------------------------------------------------------------------------
def test_privileged_netns_cmd_runner_unprivileged(monkeypatch):
    """Verify that privileged_netns_cmd_runner falls back cleanly without crashing."""
    # Mock os.geteuid to return non-zero (non-root)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    # Mock run_helper to return simulated failure
    from xrlids.demo import privileged_runner
    monkeypatch.setattr(
        privileged_runner,
        "run_helper",
        lambda cmd, args, timeout_s: (False, {"returncode": 1}, "Elevated privileges required."),
    )

    cmd = ["ip", "netns", "exec", "xrlids_vic_01", "iptables", "-C", "INPUT", "-s", "10.200.1.2", "-j", "DROP"]
    res = privileged_netns_cmd_runner(cmd)

    assert isinstance(res, subprocess.CompletedProcess)
    assert res.returncode != 0
    assert "Elevated privileges required" in res.stderr


# ---------------------------------------------------------------------------
# 6. Benign Normal Ping End-to-End Pipeline
# ---------------------------------------------------------------------------
def test_benign_normal_ping_pipeline(tmp_path):
    """Verify that a normal benign ping (5 pkts) results in BENIGN and ALLOW."""
    event_mgr = EventManager(audit_log_path=tmp_path / "events.jsonl")
    pipeline = ActiveInferencePipeline(event_manager=event_mgr, explain_all=True)

    builder = CanonicalFlowBuilder(idle_timeout_s=120.0, icmp_idle_timeout_s=2.0)

    # 5 ping requests spaced 1 second apart
    t_start = 2000.0
    for i in range(5):
        pkt = PacketInfo(
            timestamp=t_start + float(i),
            packet_length=84,
            src_ip="10.200.1.2",
            dst_ip="10.200.1.3",
            src_port=0,
            dst_port=0,
            protocol=1,
            is_tcp=False,
        )
        builder.process_packet(pkt)

    flows = builder.check_timeouts(now=t_start + 4.0 + 2.1)
    assert len(flows) == 1
    flow = flows[0]

    res = pipeline.process_flow(flow, source_mode="REAL LIVE CAPTURE")

    # Assertions
    assert res.source_mode == "REAL LIVE CAPTURE"
    assert res.protocol == 1
    assert flow.packet_count == 5
    assert len(res.rule_matches) == 0  # No rule violations
    assert res.inference.prediction_label == "BENIGN"
    assert res.inference.attack_score < 0.50
    assert res.hybrid.is_attack is False
    assert res.response.action == Action.ALLOW
    assert res.enforced_action == Action.ALLOW


# ---------------------------------------------------------------------------
# 7. Privileged Helper Collision Guard
# ---------------------------------------------------------------------------
def test_lab_helper_refuses_foreign_namespaces(monkeypatch):
    """Verify that helper refuses to destroy foreign/unknown namespaces."""
    import scripts.demo.lab_privileged_helper as helper

    # Mock root check to pass
    monkeypatch.setattr(helper, "check_root", lambda: None)
    # Mock existing namespaces with collision
    monkeypatch.setattr(helper, "get_existing_namespaces", lambda: [helper.ATTACKER_NS, helper.VICTIM_NS])
    # Mock is_owned_lab to return False (foreign namespaces)
    monkeypatch.setattr(helper, "is_owned_lab", lambda: False)

    res = helper.setup_lab()
    assert res["success"] is False
    assert "not verified as owned by XRL-IDARS" in res["error"]

