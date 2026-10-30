"""Runtime Source-IP Activity Tracker and Escalation Policy for XRL-IDARS.

Maintains independent per-source-IP state tracking for the two-stage
intrusion detection architecture:
- Stage 1: Evaluates every flow via Random Forest.
- Escalation: When a source IP generates N suspicious flows within a rolling
  time window (default: 5 flows in 60 seconds), escalation is triggered.
- Stage 2: Selectively activates the trained LSTM for temporal sequence analysis.

Guarantees:
1. Strict per-source-IP state isolation (histories never cross IP boundaries).
2. Time-window rolling expiration (stale events are purged).
3. Cooldown protection against repetitive re-escalation thrash.
4. Bounded memory consumption with LRU eviction and stale entry pruning.
5. Thread-safe concurrent access.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np


@dataclass
class HostActivityRecord:
    """State record for a single tracked source IP."""

    source_ip: str
    suspicious_timestamps: deque[float] = field(default_factory=deque)
    recent_flow_features: deque[np.ndarray] = field(default_factory=lambda: deque(maxlen=10))
    total_flows: int = 0
    total_suspicious: int = 0
    last_seen_timestamp: float = 0.0
    is_escalated: bool = False
    last_escalation_timestamp: float = 0.0
    escalation_count: int = 0

    def purge_expired(self, current_time: float, window_seconds: float) -> None:
        """Purge timestamps older than the rolling window."""
        cutoff = current_time - window_seconds
        while self.suspicious_timestamps and self.suspicious_timestamps[0] < cutoff:
            self.suspicious_timestamps.popleft()


@dataclass(frozen=True)
class EscalationDecision:
    """Result of evaluating a flow for source-IP escalation."""

    source_ip: str
    is_suspicious: bool
    suspicious_count: int
    threshold: int
    time_window_seconds: float
    escalate: bool
    reason: str
    cooldown_active: bool
    has_sufficient_lstm_history: bool
    sequence_length: int
    escalation_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "is_suspicious": self.is_suspicious,
            "suspicious_count": self.suspicious_count,
            "threshold": self.threshold,
            "time_window_seconds": self.time_window_seconds,
            "escalate": self.escalate,
            "reason": self.reason,
            "cooldown_active": self.cooldown_active,
            "has_sufficient_lstm_history": self.has_sufficient_lstm_history,
            "sequence_length": self.sequence_length,
            "escalation_count": self.escalation_count,
        }


class SourceActivityTracker:
    """Thread-safe source IP activity tracker and escalation policy engine."""

    def __init__(
        self,
        suspicious_flow_threshold: int = 5,
        time_window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
        required_lstm_sequence_length: int = 5,
        max_tracked_ips: int = 10000,
        stale_cleanup_interval_seconds: float = 300.0,
        window_seconds: float | None = None,
        escalation_threshold: int | None = None,
    ) -> None:
        """Initialize the tracker.

        Args:
            suspicious_flow_threshold: Number of suspicious flows in window to trigger escalation.
            time_window_seconds: Rolling temporal window for counting suspicious events.
            cooldown_seconds: Minimum duration after escalation before a new escalation can trigger.
            required_lstm_sequence_length: Temporal sequence length required by the LSTM (T=5).
            max_tracked_ips: Upper bound on tracked IP records to prevent memory exhaustion.
            stale_cleanup_interval_seconds: Pruning threshold for inactive IP records.
        """
        if window_seconds is not None:
            time_window_seconds = window_seconds
        if escalation_threshold is not None:
            suspicious_flow_threshold = escalation_threshold
        self.suspicious_flow_threshold = max(1, int(suspicious_flow_threshold))
        self.time_window_seconds = max(1.0, float(time_window_seconds))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.required_lstm_sequence_length = max(1, int(required_lstm_sequence_length))
        self.max_tracked_ips = max(100, int(max_tracked_ips))
        self.stale_cleanup_interval_seconds = max(60.0, float(stale_cleanup_interval_seconds))

        self._records: dict[str, HostActivityRecord] = {}
        self._lock = threading.Lock()
        self._last_prune_time = time.time()

    @property
    def window_seconds(self) -> float:
        return self.time_window_seconds

    @property
    def escalation_threshold(self) -> int:
        return self.suspicious_flow_threshold

    def reset(self) -> None:
        """Clear all host activity records."""
        with self._lock:
            self._records.clear()

    def is_in_cooldown(self, source_ip: str, current_time: float | None = None) -> bool:
        """Check if a source IP is currently in escalation cooldown."""
        now = time.time() if current_time is None else float(current_time)
        clean_ip = str(source_ip).strip() or "0.0.0.0"
        with self._lock:
            rec = self._records.get(clean_ip)
            if rec is None or rec.last_escalation_timestamp <= 0.0:
                return False
            return (now - rec.last_escalation_timestamp) < self.cooldown_seconds

    def record_flow(
        self,
        source_ip: str,
        is_suspicious: bool,
        feature_vector: np.ndarray | None = None,
        timestamp: float | None = None,
    ) -> EscalationDecision:
        """Record flow arrival for a source IP and evaluate the escalation policy.

        Args:
            source_ip: Originating IP address of the flow.
            is_suspicious: Whether the flow was classified as suspicious/attack by Stage 1.
            feature_vector: Optional scaled feature vector to append to per-source temporal buffer.
            timestamp: Event epoch timestamp; defaults to current wall-clock time.

        Returns:
            EscalationDecision specifying whether Stage 2 LSTM should be activated.
        """
        now = time.time() if timestamp is None else float(timestamp)
        clean_ip = str(source_ip).strip() or "0.0.0.0"

        with self._lock:
            # Periodic prune of stale records if max capacity approached
            if len(self._records) >= self.max_tracked_ips or (now - self._last_prune_time) > self.stale_cleanup_interval_seconds:
                self._prune_stale(now)

            if clean_ip not in self._records:
                self._records[clean_ip] = HostActivityRecord(source_ip=clean_ip)

            record = self._records[clean_ip]
            record.total_flows += 1
            record.last_seen_timestamp = now

            # Append feature vector to per-source temporal history buffer
            if feature_vector is not None:
                record.recent_flow_features.append(np.asarray(feature_vector, dtype=np.float32))

            # Purge expired timestamps from rolling window
            record.purge_expired(now, self.time_window_seconds)

            # Record suspicious event if flagged
            if is_suspicious:
                record.total_suspicious += 1
                record.suspicious_timestamps.append(now)

            suspicious_count = len(record.suspicious_timestamps)
            cooldown_active = False

            # Check cooldown status
            if record.last_escalation_timestamp > 0.0:
                elapsed_since_esc = now - record.last_escalation_timestamp
                if elapsed_since_esc < self.cooldown_seconds:
                    cooldown_active = True

            # Evaluate escalation trigger
            escalate = False
            reason = "BELOW_THRESHOLD"

            if suspicious_count >= self.suspicious_flow_threshold:
                if cooldown_active:
                    reason = "COOLDOWN_ACTIVE"
                else:
                    escalate = True
                    record.is_escalated = True
                    record.last_escalation_timestamp = now
                    record.escalation_count += 1
                    reason = "THRESHOLD_MET"

            has_history = len(record.recent_flow_features) >= self.required_lstm_sequence_length
            seq_len = len(record.recent_flow_features)

            return EscalationDecision(
                source_ip=clean_ip,
                is_suspicious=is_suspicious,
                suspicious_count=suspicious_count,
                threshold=self.suspicious_flow_threshold,
                time_window_seconds=self.time_window_seconds,
                escalate=escalate,
                reason=reason,
                cooldown_active=cooldown_active,
                has_sufficient_lstm_history=has_history,
                sequence_length=seq_len,
                escalation_count=record.escalation_count,
            )

    def get_sequence(
        self,
        source_ip: str,
        length: int | None = None,
    ) -> list[np.ndarray] | None:
        """Retrieve recent temporal sequence of features for a specific source IP.

        Returns:
            List of feature vectors of length `length`, or None if insufficient history.
        """
        req_len = length or self.required_lstm_sequence_length
        clean_ip = str(source_ip).strip() or "0.0.0.0"

        with self._lock:
            record = self._records.get(clean_ip)
            if record is None:
                return None
            if len(record.recent_flow_features) < req_len:
                return None
            # Return last req_len items in chronological order
            items = list(record.recent_flow_features)
            return items[-req_len:]

    def get_host_status(self, source_ip: str, timestamp: float | None = None) -> dict[str, Any] | None:
        """Return diagnostic status dictionary for a tracked host."""
        clean_ip = str(source_ip).strip()
        with self._lock:
            record = self._records.get(clean_ip)
            if record is None:
                return None
            now = timestamp if timestamp is not None else (record.last_seen_timestamp if record.last_seen_timestamp > 0 else time.time())
            record.purge_expired(now, self.time_window_seconds)
            in_cooldown = (now - record.last_escalation_timestamp) < self.cooldown_seconds if record.last_escalation_timestamp > 0 else False
            return {
                "source_ip": record.source_ip,
                "total_flows": record.total_flows,
                "total_suspicious": record.total_suspicious,
                "active_suspicious_in_window": len(record.suspicious_timestamps),
                "threshold": self.suspicious_flow_threshold,
                "window_seconds": self.time_window_seconds,
                "is_escalated": record.is_escalated,
                "cooldown_active": in_cooldown,
                "escalation_count": record.escalation_count,
                "buffered_flows": len(record.recent_flow_features),
                "last_seen": record.last_seen_timestamp,
            }

    def get_all_tracked_hosts(self) -> list[dict[str, Any]]:
        """Return status summary for all currently tracked hosts."""
        with self._lock:
            ips = list(self._records.keys())
        statuses = []
        for ip in ips:
            st = self.get_host_status(ip)
            if st is not None:
                statuses.append(st)
        return statuses

    def reset_host(self, source_ip: str) -> bool:
        """Reset state for a specific source IP."""
        clean_ip = str(source_ip).strip()
        with self._lock:
            if clean_ip in self._records:
                del self._records[clean_ip]
                return True
            return False

    def reset_all(self) -> None:
        """Reset all tracked host histories."""
        with self._lock:
            self._records.clear()

    def _prune_stale(self, current_time: float) -> None:
        """Prune inactive records to enforce bounded memory."""
        cutoff = current_time - self.stale_cleanup_interval_seconds
        stale_keys = [
            ip for ip, rec in self._records.items()
            if rec.last_seen_timestamp < cutoff and not rec.suspicious_timestamps
        ]
        for k in stale_keys:
            del self._records[k]

        # If still above capacity, evict oldest by last seen
        if len(self._records) > self.max_tracked_ips:
            sorted_ips = sorted(
                self._records.items(),
                key=lambda item: item[1].last_seen_timestamp,
            )
            excess = len(self._records) - self.max_tracked_ips
            for ip, _ in sorted_ips[:excess]:
                del self._records[ip]

        self._last_prune_time = current_time
