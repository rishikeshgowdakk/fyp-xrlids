"""Unit tests for pure-Python PCAP parsing and packet serialization."""

import socket
import struct
from pathlib import Path

from xrlids.demo.pcap import (
    LINKTYPE_ETHERNET,
    PacketInfo,
    PcapReader,
    build_raw_packet,
    parse_packet_bytes,
    write_pcap,
)


def test_build_and_parse_tcp_packet():
    """Verify raw TCP packet building and parsing roundtrip."""
    raw = build_raw_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol=6,
        flags={"syn": True, "ack": False, "rst": False, "fin": False},
        payload_len=128,
    )
    assert len(raw) > 34

    pkt = parse_packet_bytes(raw, timestamp=1700000000.123456)
    assert pkt is not None
    assert pkt.timestamp == 1700000000.123456
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "10.0.0.1"
    assert pkt.src_port == 54321
    assert pkt.dst_port == 80
    assert pkt.protocol == 6
    assert pkt.is_tcp is True
    assert pkt.syn is True
    assert pkt.ack is False
    assert pkt.rst is False
    assert pkt.fin is False
    assert pkt.packet_length >= 128


def test_build_and_parse_udp_packet():
    """Verify raw UDP packet building and parsing."""
    raw = build_raw_packet(
        src_ip="192.168.1.20",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol=17,
        payload_len=64,
    )
    pkt = parse_packet_bytes(raw, timestamp=1700000001.0)
    assert pkt is not None
    assert pkt.protocol == 17
    assert pkt.is_tcp is False
    assert pkt.src_port == 53000
    assert pkt.dst_port == 53
    assert pkt.packet_length >= 64


def test_parse_invalid_or_truncated_bytes():
    """Malformed or short packets should return None without raising."""
    assert parse_packet_bytes(b"", 1.0) is None
    assert parse_packet_bytes(b"\x00" * 10, 1.0) is None
    # Invalid ether type (not 0x0800 IPv4)
    invalid_eth = b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 20
    assert parse_packet_bytes(invalid_eth, 1.0) is None


def test_pcap_file_roundtrip(tmp_path: Path):
    """Verify writing and reading a PCAP file."""
    pcap_file = tmp_path / "test.pcap"
    p1 = build_raw_packet("10.0.0.1", "10.0.0.2", 1234, 80, 6, {"syn": True})
    p2 = build_raw_packet("10.0.0.2", "10.0.0.1", 80, 1234, 6, {"syn": True, "ack": True})
    packets = [(100.0, p1), (100.05, p2)]

    write_pcap(pcap_file, packets)
    assert pcap_file.exists()

    reader = PcapReader(pcap_file)
    read_pkts = list(reader.read_packets())
    assert len(read_pkts) == 2
    assert read_pkts[0].src_ip == "10.0.0.1"
    assert read_pkts[1].src_ip == "10.0.0.2"
    assert read_pkts[0].syn is True
    assert read_pkts[1].ack is True
