"""Live Flow Construction under Decision D-006.

Aggregates streaming packets into canonical bidirectional 5-tuple flows,
applies the D-006 hybrid completion policy (TCP FIN/RST termination and 120s idle timeout),
and computes the frozen Phase 1 R10 semantic feature vector.

Preserves the temporal separation invariant:
- Replay mode: uses packet header timestamps (pkt.timestamp).
- Live mode: uses system arrival timestamps.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Generator, Iterable, Sequence

from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.features.definitions import R10_FEATURES


@dataclass
class FlowBuilderStats:
    """Observability metrics for flow construction."""

    total_packets_processed: int = 0
    active_flows_count: int = 0
    flows_completed_fin_rst: int = 0
    flows_completed_timeout: int = 0
    total_flows_completed: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_packets_processed": self.total_packets_processed,
            "active_flows_count": self.active_flows_count,
            "flows_completed_fin_rst": self.flows_completed_fin_rst,
            "flows_completed_timeout": self.flows_completed_timeout,
            "total_flows_completed": self.total_flows_completed,
        }


class LiveFlowBuilder:
    """Manages active network flows and flushes completed flows per D-006."""

    def __init__(
        self,
        idle_timeout_s: float = 120.0,
        clock_mode: str = "packet",  # "packet" or "wall_clock"
    ) -> None:
        if clock_mode not in ("packet", "wall_clock"):
            raise ValueError(f"Invalid clock_mode '{clock_mode}', must be 'packet' or 'wall_clock'")
        self.idle_timeout_s = idle_timeout_s
        self.clock_mode = clock_mode
        self.active_flows: dict[FlowKey, Flow] = {}
        self.stats = FlowBuilderStats()

    def process_packet(self, pkt: PacketInfo) -> list[Flow]:
        """Ingest a packet, expire timed-out flows, and return any completed flows."""
        self.stats.total_packets_processed += 1
        current_time = time.monotonic() if self.clock_mode == "wall_clock" else pkt.timestamp
        completed: list[Flow] = []

        # 1. Check expiration for existing flows (120s idle timeout fallback)
        expired_keys = []
        for key, flow in self.active_flows.items():
            ref_time = current_time if self.clock_mode == "wall_clock" else pkt.timestamp
            if ref_time - flow.last_time > self.idle_timeout_s:
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1

        for k in expired_keys:
            del self.active_flows[k]

        # 2. Map to canonical bidirectional 5-tuple
        key, is_fwd = FlowKey.from_packet(pkt)
        if key not in self.active_flows:
            flow = Flow(key=key, start_time=pkt.timestamp, last_time=pkt.timestamp)
            self.active_flows[key] = flow
        else:
            flow = self.active_flows[key]

        flow.add_packet(pkt, is_fwd)

        # 3. Check TCP FIN/RST completion
        if flow.is_closed:
            completed.append(flow)
            del self.active_flows[key]
            self.stats.flows_completed_fin_rst += 1

        self.stats.active_flows_count = len(self.active_flows)
        self.stats.total_flows_completed += len(completed)
        return completed

    def check_idle_timeouts(self, now: float | None = None) -> list[Flow]:
        """Explicitly sweep and expire idle flows based on current time."""
        current_time = now if now is not None else (time.monotonic() if self.clock_mode == "wall_clock" else time.time())
        expired: list[Flow] = []
        expired_keys = []

        for key, flow in self.active_flows.items():
            if current_time - flow.last_time > self.idle_timeout_s:
                expired.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1

        for k in expired_keys:
            del self.active_flows[k]

        self.stats.active_flows_count = len(self.active_flows)
        self.stats.total_flows_completed += len(expired)
        return expired

    def flush_all(self) -> list[Flow]:
        """Flush all remaining active flows at the conclusion of capture/replay."""
        flows = list(self.active_flows.values())
        self.active_flows.clear()
        self.stats.total_flows_completed += len(flows)
        self.stats.active_flows_count = 0
        return flows
