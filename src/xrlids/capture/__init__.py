"""Unified Packet Capture & PCAP Replay Service for XRL-IDARS.

Provides Scapy-backed live sniffing, PCAP file replay, and raw header extraction.
"""

from __future__ import annotations

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.capture.scapy_service import (
    CapturePermissionError,
    CaptureStats,
    ScapyCaptureConfig,
    ScapyCaptureService,
    scapy_packet_to_packet_info,
)

__all__ = [
    "CapturePermissionError",
    "CaptureStats",
    "LiveCaptureManager",
    "ScapyCaptureConfig",
    "ScapyCaptureService",
    "scapy_packet_to_packet_info",
]
