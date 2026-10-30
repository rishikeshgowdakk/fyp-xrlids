"""Unit tests for LiveCaptureManager (Phase 2)."""

import threading
import time
import pytest

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.demo.pcap import PacketInfo
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline


def test_live_manager_initialization():
    mgr = LiveCaptureManager()
    assert mgr.status == "IDLE"
    assert not mgr.is_running
    assert len(mgr.completed_flows) == 0
    stats = mgr.get_stats()
    assert stats["status"] == "IDLE"
    assert stats["packets_captured"] == 0
    assert stats["active_flows"] == 0
    assert stats["completed_flows"] == 0


def test_live_manager_interfaces_and_permissions():
    mgr = LiveCaptureManager()
    ifaces = mgr.get_available_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "lo" in ifaces

    has_perm, msg = mgr.check_permissions()
    assert isinstance(has_perm, bool)
    assert isinstance(msg, str)


def test_live_manager_blocked_when_unprivileged(monkeypatch):
    mgr = LiveCaptureManager()
    # Force check_permissions to return False
    monkeypatch.setattr(mgr, "check_permissions", lambda: (False, "CAP_NET_RAW capability missing"))

    success, message = mgr.start(interface="lo")
    assert not success
    assert mgr.status == "BLOCKED"
    assert "CAP_NET_RAW" in message
    assert mgr.last_error is not None
    assert not mgr.is_running


def test_live_manager_packet_processing_and_flushing(tmp_path):
    audit_file = tmp_path / "live_events.jsonl"
    event_mgr = EventManager(audit_log_path=audit_file)
    pipeline = ActiveInferencePipeline(event_manager=event_mgr)
    mgr = LiveCaptureManager(pipeline=pipeline, event_manager=event_mgr)

    # Simulate arrival of TCP packets forming a flow
    t0 = time.time()
    # SYN packet
    pkt_syn = PacketInfo(
        timestamp=t0,
        packet_length=64,
        src_ip="10.200.1.50",
        dst_ip="192.168.10.80",
        src_port=44556,
        dst_port=80,
        protocol=6,
        is_tcp=True,
        syn=True,
    )
    # FIN packet
    pkt_fin = PacketInfo(
        timestamp=t0 + 0.1,
        packet_length=64,
        src_ip="10.200.1.50",
        dst_ip="192.168.10.80",
        src_port=44556,
        dst_port=80,
        protocol=6,
        is_tcp=True,
        fin=True,
    )

    # Process through flow builder directly
    completed = mgr.flow_builder.process_packet(pkt_syn)
    assert len(completed) == 0

    completed = mgr.flow_builder.process_packet(pkt_fin)
    assert len(completed) == 1
    flow = completed[0]

    # Process through pipeline
    res = mgr.pipeline.process_flow(flow)
    assert res.flow_id is not None
    assert len(event_mgr.get_recent_events()) == 1

    # Verify stop flushes clean
    stats = mgr.stop()
    assert stats["status"] == "STOPPED"
