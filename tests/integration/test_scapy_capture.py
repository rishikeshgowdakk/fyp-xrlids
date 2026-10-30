"""Integration tests for Scapy Packet Capture and PCAP Replay service."""

from pathlib import Path
import pytest

from xrlids.capture.scapy_service import (
    CapturePermissionError,
    ScapyCaptureService,
    scapy_packet_to_packet_info,
)
from xrlids.flow.canonical_builder import CanonicalFlowBuilder

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PCAP = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"


def test_scapy_list_interfaces():
    service = ScapyCaptureService()
    ifaces = service.list_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0  # At least 'lo' should exist on linux


def test_scapy_permission_check():
    service = ScapyCaptureService()
    has_perm, reason = service.check_raw_capture_permission()
    assert isinstance(has_perm, bool)
    assert isinstance(reason, str)
    assert len(reason) > 0


def test_scapy_pcap_replay_and_flow_builder():
    if not SAMPLE_PCAP.exists():
        pytest.skip(f"Sample PCAP not found: {SAMPLE_PCAP}")

    service = ScapyCaptureService()
    flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)

    packets = list(service.replay_pcap(SAMPLE_PCAP, max_packets=50))
    assert len(packets) > 0

    all_completed_flows = []
    for pkt in packets:
        assert pkt.packet_length > 0
        assert pkt.src_ip != ""
        assert pkt.dst_ip != ""
        completed = flow_builder.process_packet(pkt)
        all_completed_flows.extend(completed)

    flushed = flow_builder.flush_all()
    all_completed_flows.extend(flushed)

    assert len(all_completed_flows) > 0
    flow = all_completed_flows[0]
    feats = flow.to_features()
    assert "flow_duration_ms" in feats
    assert "syn_ack_ratio" in feats
    assert service.stats.packets_captured == len(packets)
    assert service.stats.bytes_captured > 0


def test_scapy_packet_to_packet_info_synthetic():
    from scapy.all import IP, TCP, Ether

    raw_pkt = Ether() / IP(src="192.168.1.50", dst="10.0.0.1", proto=6) / TCP(sport=54321, dport=443, flags="SA")
    raw_pkt.time = 1234567.89

    info = scapy_packet_to_packet_info(raw_pkt)
    assert info is not None
    assert info.src_ip == "192.168.1.50"
    assert info.dst_ip == "10.0.0.1"
    assert info.src_port == 54321
    assert info.dst_port == 443
    assert info.is_tcp is True
    assert info.syn is True
    assert info.ack is True
    assert info.rst is False
    assert info.fin is False
    assert info.timestamp == pytest.approx(1234567.89)
