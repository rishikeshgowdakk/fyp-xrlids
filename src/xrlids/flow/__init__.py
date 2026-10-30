"""Canonical Flow Processing Layer for XRL-IDARS.

Provides bidirectional 5-tuple flow aggregation, TCP state tracking,
idle timeout (120s) expiration, and R10 feature extraction.
"""

from xrlids.flow.canonical_builder import (
    CanonicalFlow,
    CanonicalFlowBuilder,
    CanonicalFlowKey,
    FlowBuilderStats,
)

__all__ = [
    "CanonicalFlowKey",
    "CanonicalFlow",
    "CanonicalFlowBuilder",
    "FlowBuilderStats",
]
