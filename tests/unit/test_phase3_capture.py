"""Unit tests for Phase 3A PacketCaptureService."""

import pytest
from pathlib import Path

from xrlids.demo.pcap import PacketInfo, build_raw_packet, parse_packet_bytes, write_pcap
from xrlids.live.capture import CaptureConfig, PacketCaptureService


def test_capture_service_synthetic_lifecycle():
    """Verify capture service processes synthetic packet streams with accurate counters."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0 + i, "192.168.1.10", "10.0.0.1", 50000 + i, 80, 6, 64, is_tcp=True)
        for i in range(25)
    ]

    service = PacketCaptureService(synthetic_stream=packets)
    captured = list(service.stream_packets())

    assert len(captured) == 25
    assert service.stats.packets_captured == 25
    assert service.stats.bytes_captured == 25 * 64
    assert service.stats.malformed_packets == 0
    assert service.stats.errors == 0
    assert service.stats.duration_s >= 0.0


def test_capture_service_max_packets_limit():
    """Verify capture service respects max_packets boundary."""
    t0 = 1700000000.0
    packets = [
        PacketInfo(t0 + i, "192.168.1.10", "10.0.0.1", 50000 + i, 80, 6, 64, is_tcp=True)
        for i in range(50)
    ]

    config = CaptureConfig(max_packets=10)
    service = PacketCaptureService(config=config, synthetic_stream=packets)
    captured = list(service.stream_packets())

    assert len(captured) == 10
    assert service.stats.packets_captured == 10


def test_capture_service_pcap_streaming(tmp_path: Path):
    """Verify capture service streams packets from a PCAP file."""
    pcap_file = tmp_path / "test_stream.pcap"
    raw_pkts = [
        (1700000000.0 + i * 0.01, build_raw_packet("192.168.1.5", "10.0.0.2", 1234, 80, payload_len=100))
        for i in range(12)
    ]
    write_pcap(pcap_file, raw_pkts)

    service = PacketCaptureService(pcap_path=pcap_file)
    streamed = list(service.stream_packets())

    assert len(streamed) == 12
    assert service.stats.packets_captured == 12
    assert all(pkt.src_ip == "192.168.1.5" for pkt in streamed)


def test_malformed_packet_handling():
    """Verify parse_packet_bytes rejects malformed/truncated frames without crashing."""
    ts = 1700000000.0

    # Truncated Ethernet (< 14 bytes)
    assert parse_packet_bytes(b"\x00" * 10, ts) is None

    # Non-IPv4 Ethernet type (e.g. ARP 0x0806)
    arp_frame = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    assert parse_packet_bytes(arp_frame, ts) is None

    # Truncated IPv4 header
    trunc_ip = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 10
    assert parse_packet_bytes(trunc_ip, ts) is None


def test_permission_detection():
    """Verify permission check returns a boolean and unprivileged live socket raises PermissionError."""
    has_cap = PacketCaptureService.check_permissions()
    assert isinstance(has_cap, bool)

    if not has_cap:
        service = PacketCaptureService()  # live mode without pcap or synthetic
        with pytest.raises(PermissionError, match="requires raw socket privileges"):
            list(service.stream_packets())
