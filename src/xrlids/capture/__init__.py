"""Network packet capture subsystem for XRL-IDARS.

Provides Scapy-based live interface capture, PCAP replay, and bounded streaming queues.
"""

from __future__ import annotations

from xrlids.capture.scapy_service import (
    CaptureStats,
    ScapyCaptureConfig,
    ScapyCaptureService,
)

__all__ = [
    "CaptureStats",
    "ScapyCaptureConfig",
    "ScapyCaptureService",
]
