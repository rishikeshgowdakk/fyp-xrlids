"""Unified Packet Capture & PCAP Replay Service for XRL-IDARS.

Provides Scapy-backed live sniffing, PCAP file replay, and raw header extraction.
"""

from xrlids.capture.scapy_service import (
    CapturePermissionError,
    CaptureStats,
    ScapyCaptureService,
    scapy_packet_to_packet_info,
)

__all__ = [
    "ScapyCaptureService",
    "CaptureStats",
    "CapturePermissionError",
    "scapy_packet_to_packet_info",
]
