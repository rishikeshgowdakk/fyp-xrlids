"""Configurable bidirectional network flow engine for XRL-IDARS (Phase 2).

Manages active flows, applies the D-006 lifecycle completion policy
(TCP FIN/RST termination, configurable idle timeout, and max lifetime timeout),
and enforces bounded memory invariants.

Guarantees:
1. Canonical bidirectional 5-tuple aggregation (forward and reverse packets map to same flow).
2. Clean TCP lifecycle termination (FIN/RST closes immediately).
3. Configurable idle timeout (default 120.0s) and maximum connection lifetime (default 1800.0s).
4. Memory safety: bounded active flows capacity prevents RAM exhaustion under volumetric attacks.
5. Observability: comprehensive counters for packets, bytes, completion causes, and errors.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from xrlids.flow.flow import Flow
from xrlids.flow.key import FlowKey

if TYPE_CHECKING:
    from xrlids.demo.pcap import PacketInfo

logger = logging.getLogger("xrlids.flow.engine")


@dataclass
class FlowEngineStats:
    """Runtime observability counters for flow engine."""

    total_packets_processed: int = 0
    total_bytes_processed: int = 0
    active_flows_count: int = 0
    flows_completed_fin: int = 0
    flows_completed_rst: int = 0
    flows_completed_timeout: int = 0
    flows_completed_max_duration: int = 0
    flows_evicted_capacity: int = 0
    total_flows_completed: int = 0
    flow_errors: int = 0
    max_active_flow_watermark: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_packets_processed": self.total_packets_processed,
            "total_bytes_processed": self.total_bytes_processed,
            "active_flows_count": self.active_flows_count,
            "flows_completed_fin": self.flows_completed_fin,
            "flows_completed_rst": self.flows_completed_rst,
            "flows_completed_timeout": self.flows_completed_timeout,
            "flows_completed_max_duration": self.flows_completed_max_duration,
            "flows_evicted_capacity": self.flows_evicted_capacity,
            "total_flows_completed": self.total_flows_completed,
            "flow_errors": self.flow_errors,
            "max_active_flow_watermark": self.max_active_flow_watermark,
        }


class FlowEngine:
    """High-performance, bounded-memory bidirectional flow engine."""

    def __init__(
        self,
        idle_timeout_s: float = 120.0,
        max_flow_duration_s: float | None = 1800.0,
        max_active_flows: int = 100_000,
        clock_mode: str = "packet",  # "packet" or "wall_clock"
    ) -> None:
        if clock_mode not in ("packet", "wall_clock"):
            raise ValueError(f"Invalid clock_mode '{clock_mode}', must be 'packet' or 'wall_clock'")
        self.idle_timeout_s = float(idle_timeout_s)
        self.max_flow_duration_s = float(max_flow_duration_s) if max_flow_duration_s is not None else None
        self.max_active_flows = int(max_active_flows)
        self.clock_mode = clock_mode
        self.active_flows: dict[FlowKey, Flow] = {}
        self.stats = FlowEngineStats()

    def process_packet(self, pkt: PacketInfo) -> list[Flow]:
        """Ingest a packet, expire timed-out flows, and return any completed flows."""
        self.stats.total_packets_processed += 1
        self.stats.total_bytes_processed += pkt.packet_length
        current_time = time.monotonic() if self.clock_mode == "wall_clock" else pkt.timestamp
        completed: list[Flow] = []

        # 1. Sweep active flows for idle timeout or maximum duration
        expired_keys: list[FlowKey] = []
        for key, flow in self.active_flows.items():
            ref_time = current_time if self.clock_mode == "wall_clock" else pkt.timestamp
            # Idle timeout check
            if ref_time - flow.last_time > self.idle_timeout_s:
                flow.is_closed = True
                flow.closed_reason = "timeout"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1
            # Maximum flow lifetime check
            elif self.max_flow_duration_s is not None and (ref_time - flow.start_time > self.max_flow_duration_s):
                flow.is_closed = True
                flow.closed_reason = "max_duration"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_max_duration += 1

        for k in expired_keys:
            del self.active_flows[k]

        # 2. Canonical 5-tuple lookup and packet aggregation
        try:
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
                if flow.closed_reason == "rst":
                    self.stats.flows_completed_rst += 1
                else:
                    self.stats.flows_completed_fin += 1

            # 4. Capacity bound enforcement (LRU eviction if active table exceeds limit)
            if len(self.active_flows) > self.max_active_flows:
                oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_time)
                evicted_flow = self.active_flows.pop(oldest_key)
                evicted_flow.is_closed = True
                evicted_flow.closed_reason = "evicted_capacity"
                completed.append(evicted_flow)
                self.stats.flows_evicted_capacity += 1

        except Exception as err:
            logger.debug("Error processing packet in FlowEngine: %s", err)
            self.stats.flow_errors += 1

        self.stats.total_flows_completed += len(completed)
        self.stats.active_flows_count = len(self.active_flows)
        self.stats.max_active_flow_watermark = max(
            self.stats.max_active_flow_watermark, self.stats.active_flows_count
        )
        return completed

    def expire_flows(self, current_time: float | None = None) -> list[Flow]:
        """Explicit sweep for timed-out or expired active flows."""
        now = current_time if current_time is not None else (
            time.monotonic() if self.clock_mode == "wall_clock" else time.time()
        )
        completed: list[Flow] = []
        expired_keys: list[FlowKey] = []

        for key, flow in self.active_flows.items():
            if now - flow.last_time > self.idle_timeout_s:
                flow.is_closed = True
                flow.closed_reason = "timeout"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_timeout += 1
            elif self.max_flow_duration_s is not None and (now - flow.start_time > self.max_flow_duration_s):
                flow.is_closed = True
                flow.closed_reason = "max_duration"
                completed.append(flow)
                expired_keys.append(key)
                self.stats.flows_completed_max_duration += 1

        for k in expired_keys:
            del self.active_flows[k]

        self.stats.total_flows_completed += len(completed)
        self.stats.active_flows_count = len(self.active_flows)
        return completed

    def flush_all(self) -> list[Flow]:
        """Flush all remaining active flows at the end of capture/replay."""
        flows: list[Flow] = []
        for flow in self.active_flows.values():
            flow.is_closed = True
            flow.closed_reason = "flushed_eof"
            flows.append(flow)
        self.stats.total_flows_completed += len(flows)
        self.active_flows.clear()
        self.stats.active_flows_count = 0
        return flows
