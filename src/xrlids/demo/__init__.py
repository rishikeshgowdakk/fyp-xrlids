"""Demonstration foundation for reproducible PCAP replay and safe observational monitoring."""

from xrlids.demo.extractor import flows_to_dataframe, verify_feature_parity
from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.live_lab import AlertEvent, LiveLabMonitor
from xrlids.demo.pcap import (
    PacketInfo,
    PcapReader,
    build_raw_packet,
    parse_packet_bytes,
    write_pcap,
)
from xrlids.demo.replay import (
    FlowPredictionEvent,
    ReplayEngine,
    ReplaySummary,
    save_demo_artifacts,
)

__all__ = [
    "AlertEvent",
    "Flow",
    "FlowBuilder",
    "FlowKey",
    "FlowPredictionEvent",
    "LiveLabMonitor",
    "PacketInfo",
    "PcapReader",
    "ReplayEngine",
    "ReplaySummary",
    "build_raw_packet",
    "flows_to_dataframe",
    "parse_packet_bytes",
    "save_demo_artifacts",
    "verify_feature_parity",
    "write_pcap",
]
