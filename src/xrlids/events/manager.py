"""Event Manager and Audit Bus for XRL-IDARS (Phase 13).

Provides thread-safe event publishing, ring-buffer caching for dashboards,
subscriber callbacks, and persistent JSONL audit logging.
"""

from __future__ import annotations

from collections import deque
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Callable

from xrlids.events.schema import SecurityEvent
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_AUDIT_LOG = REPO_ROOT / "results" / "audits" / "security_events.jsonl"


class EventManager:
    """Thread-safe event dispatcher and auditor."""

    def __init__(
        self,
        max_buffer_size: int = 5000,
        audit_log_path: Path | str | None = None,
        persist_to_disk: bool = True,
    ) -> None:
        self.max_buffer_size = max_buffer_size
        self.persist_to_disk = persist_to_disk
        self.audit_log_path = Path(audit_log_path or DEFAULT_AUDIT_LOG)
        if self.persist_to_disk:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._buffer: deque[SecurityEvent] = deque(maxlen=max_buffer_size)
        self._subscribers: list[Callable[[SecurityEvent], None]] = []

        self.total_events: int = 0
        self.threat_events: int = 0
        self.rule_matches_count: int = 0
        self.escalated_events_count: int = 0

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a subscriber callback for real-time event notifications."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Unregister a subscriber callback."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: SecurityEvent) -> None:
        """Publish a new security event to the buffer, disk, and subscribers."""
        with self._lock:
            self._buffer.append(event)
            self.total_events += 1

            if event.hybrid_verdict in ("RF", "RULE", "HYBRID"):
                self.threat_events += 1
            if event.rule_matches:
                self.rule_matches_count += len(event.rule_matches)
            if event.source_escalated:
                self.escalated_events_count += 1

            # Append to persistent JSONL log
            if self.persist_to_disk:
                try:
                    with open(self.audit_log_path, "a", encoding="utf-8") as f:
                        f.write(event.to_json() + "\n")
                except Exception as e:
                    logger.warning("Could not append event to %s: %s", self.audit_log_path, e)

            # Notify subscribers
            subscribers_copy = list(self._subscribers)

        for sub in subscribers_copy:
            try:
                sub(event)
            except Exception as e:
                logger.error("Error executing event subscriber callback: %s", e)

    def get_recent_events(
        self,
        limit: int = 50,
        severity_filter: str | None = None,
        verdict_filter: str | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve recent events from the ring buffer with optional filtering."""
        with self._lock:
            events = list(self._buffer)

        if severity_filter:
            sev_upper = severity_filter.upper()
            events = [e for e in events if e.severity == sev_upper]

        if verdict_filter:
            verd_upper = verdict_filter.upper()
            events = [e for e in events if e.hybrid_verdict == verd_upper]

        return events[-limit:]

    def get_stats(self) -> dict[str, int]:
        """Return operational counters."""
        with self._lock:
            return {
                "total_events": self.total_events,
                "threat_events": self.threat_events,
                "rule_matches_count": self.rule_matches_count,
                "escalated_events_count": self.escalated_events_count,
                "buffer_size": len(self._buffer),
            }

    def clear(self) -> None:
        """Clear memory buffer and counters."""
        with self._lock:
            self._buffer.clear()
            self.total_events = 0
            self.threat_events = 0
            self.rule_matches_count = 0
            self.escalated_events_count = 0
