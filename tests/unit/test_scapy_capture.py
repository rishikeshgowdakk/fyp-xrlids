"""Unit tests for Scapy-based network packet capture and PCAP replay service."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from xrlids.capture.scapy_service import (
    CaptureStats,
    ScapyCaptureConfig,
    ScapyCaptureService,
    scapy_packet_to_packet_info,
)
from xrlids.demo.pcap import PacketInfo

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PCAP = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"


def test_scapy_capture_config_defaults():
    """Verify ScapyCaptureConfig sensible default parameters."""
    cfg = ScapyCaptureConfig()
    assert cfg.interface is None
    assert cfg.bpf_filter is None
    assert cfg.queue_size == 10000
    assert cfg.pcap_replay_speed_factor == 0.0


def test_scapy_capture_stats_calculations():
    """Verify CaptureStats duration, rate, and dictionary serialization."""
    stats = CaptureStats(start_time=100.0, stop_time=105.0, packets_captured=500, bytes_captured=250000)
    assert stats.duration_s == 5.0
    assert stats.packets_per_second == 100.0
    d = stats.to_dict()
    assert d["packets_captured"] == 500
    assert d["packets_per_second"] == 100.0
    assert d["duration_s"] == 5.0


def test_scapy_packet_conversion_with_mock():
    """Verify scapy_packet_to_packet_info extracts TCP flags and 5-tuple."""
    from scapy.all import IP, TCP, Ether

    pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="SA")
    pkt.time = 1700000000.123

    info = scapy_packet_to_packet_info(pkt)
    assert info is not None
    assert info.src_ip == "192.168.1.10"
    assert info.dst_ip == "10.0.0.1"
    assert info.src_port == 54321
    assert info.dst_port == 80
    assert info.protocol == 6
    assert info.is_tcp is True
    assert info.syn is True
    assert info.ack is True
    assert info.rst is False
    assert info.fin is False
    assert info.timestamp == 1700000000.123


def test_scapy_pcap_replay_streaming():
    """Verify ScapyCaptureService streams genuine packets from sample_traffic.pcap."""
    assert SAMPLE_PCAP.exists(), f"Sample PCAP missing at {SAMPLE_PCAP}"

    cfg = ScapyCaptureConfig(pcap_path=SAMPLE_PCAP, max_packets=50, queue_size=100)
    service = ScapyCaptureService(cfg)
    service.start()

    packets = []
    deadline = time.time() + 5.0
    while len(packets) < 50 and time.time() < deadline:
        pkt = service.get_packet(timeout=0.2)
        if pkt is not None:
            packets.append(pkt)
        elif not service.is_running:
            break

    service.stop()

    assert len(packets) > 0
    first = packets[0]
    assert isinstance(first, PacketInfo)
    assert first.src_ip != ""
    assert first.dst_ip != ""
    assert first.packet_length > 0
    assert service.stats.packets_captured == len(packets)
    assert service.stats.bytes_captured > 0


def test_scapy_check_permissions():
    """Verify check_permissions returns a boolean without unhandled exceptions."""
    perm = ScapyCaptureService.check_permissions()
    assert isinstance(perm, bool)
