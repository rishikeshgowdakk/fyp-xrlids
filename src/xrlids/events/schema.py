"""Canonical Security Event Schema for XRL-IDARS (Phase 13).

Provides a unified, JSON-serializable event structure integrating ML perception,
TreeSHAP explainability, deterministic rules, source activity tracking, and response policy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import uuid
from typing import Any


@dataclass
class SecurityEvent:
    """Standardized XRL-IDARS Security Event."""

    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: str = ""
    source_mode: str = "LIVE"  # "LIVE", "PCAP", "SAMPLE"
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    protocol: int = 6  # TCP=6, UDP=17

    # Perception Tier
    features: dict[str, float] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)

    # Behavioural & Rule Tier
    rule_matches: list[dict[str, Any]] = field(default_factory=list)
    hybrid_verdict: str = "BENIGN"  # "BENIGN", "RF", "RULE", "HYBRID"
    severity: str = "NONE"  # "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    source_escalated: bool = False
    source_status: dict[str, Any] = field(default_factory=dict)

    # Explainability Tier
    explanation: dict[str, Any] | None = None

    # Decision & Response Tier
    response: dict[str, Any] = field(default_factory=dict)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert security event to dictionary."""
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        """Convert security event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Reconstruct security event from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
