"""Live Network Validation & Controlled Autonomous Response (Phase 3).

Establishes a scientifically controlled bridge from frozen offline evidence
to real-time streaming packet capture, live flow assembly under D-006,
numerical feature parity, and dry-run autonomous response.
"""

from __future__ import annotations

from xrlids.live.capture import CaptureConfig, CaptureStats, PacketCaptureService
from xrlids.live.flow_builder import FlowBuilderStats, LiveFlowBuilder
from xrlids.live.observability import (
    BackpressureDropEvent,
    BoundedFlowQueue,
    FailureInjectionHarness,
    HealthConfig,
    HealthMonitor,
    HealthReport,
    HealthState,
)
from xrlids.live.parity import LiveFeatureParityHarness, ParityResult
from xrlids.live.runner import DryRunAuditor, LiveMode, LivePipelineRunner

__all__ = [
    "BackpressureDropEvent",
    "BoundedFlowQueue",
    "CaptureConfig",
    "CaptureStats",
    "DryRunAuditor",
    "FailureInjectionHarness",
    "FlowBuilderStats",
    "HealthConfig",
    "HealthMonitor",
    "HealthReport",
    "HealthState",
    "LiveFeatureParityHarness",
    "LiveFlowBuilder",
    "LiveMode",
    "LivePipelineRunner",
    "PacketCaptureService",
    "ParityResult",
]
