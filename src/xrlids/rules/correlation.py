"""Deterministic Multi-Flow Port Scan Correlation Engine for XRL-IDARS.

Provides stateful, time-windowed cross-flow correlation to detect horizontal and vertical
port scans that span multiple independent 5-tuple flows (RFC 4987 / NIST SP 800-94).
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Sequence


@dataclass
class DestinationProbeRecord:
    """Tracks probe activity from a source IP to a specific destination IP within the correlation window."""

    dest_ip: str
    ports: set[int] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    probe_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    alert_emitted: bool = False

    def purge_expired_ports(self, cutoff: float) -> None:
        """Purge activity if last seen timestamp is before the cutoff window."""
        if self.last_seen < cutoff:
            self.ports.clear()
            self.probe_count = 0
            self.syn_count = 0
            self.ack_count = 0
            self.alert_emitted = False


@dataclass
class SourceProbeState:
    """Tracks stateful probe activity for a single source IP."""

    source_ip: str
    destinations: dict[str, DestinationProbeRecord] = field(default_factory=dict)
    all_unique_ports: set[int] = field(default_factory=set)
    total_probes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    alert_emitted: bool = False

    def purge_stale_destinations(self, cutoff: float) -> None:
        """Remove destinations with no activity since cutoff."""
        stale = [dst for dst, rec in self.destinations.items() if rec.last_seen < cutoff]
        for dst in stale:
            del self.destinations[dst]

        # Recompute aggregate unique ports from active destinations
        self.all_unique_ports = set()
        for rec in self.destinations.values():
            self.all_unique_ports.update(rec.ports)

        if not self.destinations:
            self.total_probes = 0
            self.alert_emitted = False


@dataclass(frozen=True)
class PortScanCorrelationResult:
    """Deterministic result of multi-flow port scan analysis."""

    is_port_scan: bool
    source_ip: str
    target_ip: str
    unique_ports_count: int
    probed_ports: list[int]
    total_probes: int
    window_seconds: float
    scan_type: str  # "VERTICAL" (one target, multiple ports) or "DISTRIBUTED" (multiple targets)
    rule_id: str = "RULE-PORT-SCAN-MULTI-FLOW"
    severity: str = "HIGH"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_port_scan": self.is_port_scan,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "unique_ports_count": self.unique_ports_count,
            "probed_ports": sorted(self.probed_ports)[:20],
            "total_probes": self.total_probes,
            "window_seconds": self.window_seconds,
            "scan_type": self.scan_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
        }


class MultiFlowPortScanCorrelator:
    """Bounded, deterministic, time-windowed correlator tracking cross-flow port scan probes.

    Maintains bounded memory and strict temporal expiration.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        min_unique_ports: int = 5,
        min_probes: int = 5,
        max_tracked_sources: int = 2000,
        stale_cleanup_interval_s: float = 120.0,
    ) -> None:
        """Initialize port scan correlator with configurable, documented thresholds.

        Parameters
        ----------
        window_seconds: float
            Temporal sliding correlation window (default: 60.0s).
        min_unique_ports: int
            Minimum number of distinct destination ports probed to declare a port scan (default: 5).
        min_probes: int
            Minimum probe flow count required within window (default: 5).
        max_tracked_sources: int
            Maximum number of source IP records to prevent memory exhaustion (default: 2000).
        stale_cleanup_interval_s: float
            Interval between periodic garbage collection passes (default: 120.0s).
        """
        self.window_seconds = max(1.0, float(window_seconds))
        self.min_unique_ports = max(2, int(min_unique_ports))
        self.min_probes = max(2, int(min_probes))
        self.max_tracked_sources = max(10, int(max_tracked_sources))
        self.stale_cleanup_interval_s = max(10.0, float(stale_cleanup_interval_s))

        self._sources: OrderedDict[str, SourceProbeState] = OrderedDict()
        self._last_cleanup = time.monotonic()
        self._lock = threading.RLock()

    def reset(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._sources.clear()
            self._last_cleanup = time.monotonic()

    def record_probe(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        timestamp: float | None = None,
        is_syn: bool = True,
        is_ack: bool = False,
    ) -> PortScanCorrelationResult | None:
        """Record an observed flow arrival and evaluate if multi-flow port scanning threshold is met.

        Parameters
        ----------
        source_ip: str
            Source IP of the connection.
        dest_ip: str
            Destination IP target.
        dest_port: int
            Destination transport port.
        timestamp: float | None
            Monotonic or epoch timestamp; defaults to time.monotonic() if None.
        is_syn: bool
            Whether flow contained SYN probes.
        is_ack: bool
            Whether flow had mutual ACK responses.

        Returns
        -------
        PortScanCorrelationResult | None
            Match result if correlation threshold is met and not previously alerted, else None.
        """
        clean_src = str(source_ip).strip()
        clean_dst = str(dest_ip).strip()
        port = int(dest_port)

        # Ignore invalid ports or missing IPs
        if not clean_src or not clean_dst or port <= 0 or port > 65535:
            return None

        now = float(timestamp) if timestamp is not None else time.monotonic()

        with self._lock:
            # Periodic background cleanup of stale source records
            if (now - self._last_cleanup) >= self.stale_cleanup_interval_s:
                self._prune_stale(now)
                self._last_cleanup = now

            # Fetch or initialize source probe state
            if clean_src in self._sources:
                src_state = self._sources[clean_src]
                self._sources.move_to_end(clean_src)
            else:
                # Bounded memory enforcement: evict oldest record if capacity exceeded
                if len(self._sources) >= self.max_tracked_sources:
                    self._sources.popitem(last=False)
                src_state = SourceProbeState(source_ip=clean_src, first_seen=now, last_seen=now)
                self._sources[clean_src] = src_state

            cutoff = now - self.window_seconds
            src_state.purge_stale_destinations(cutoff)

            # Update overall source timestamps (handling out-of-order timestamps gracefully)
            if src_state.first_seen <= 0.0 or now < src_state.first_seen:
                src_state.first_seen = now
            if now > src_state.last_seen:
                src_state.last_seen = now

            # Fetch or initialize destination record
            if clean_dst not in src_state.destinations:
                dst_rec = DestinationProbeRecord(
                    dest_ip=clean_dst,
                    first_seen=now,
                    last_seen=now,
                )
                src_state.destinations[clean_dst] = dst_rec
            else:
                dst_rec = src_state.destinations[clean_dst]
                if dst_rec.first_seen <= 0.0 or now < dst_rec.first_seen:
                    dst_rec.first_seen = now
                if now > dst_rec.last_seen:
                    dst_rec.last_seen = now

            # Update probe stats
            dst_rec.ports.add(port)
            dst_rec.probe_count += 1
            if is_syn:
                dst_rec.syn_count += 1
            if is_ack:
                dst_rec.ack_count += 1

            src_state.all_unique_ports.add(port)
            src_state.total_probes += 1

            # Check Vertical Port Scan: probing multiple ports on a SINGLE target
            target_unique_ports = len(dst_rec.ports)
            if target_unique_ports >= self.min_unique_ports and dst_rec.probe_count >= self.min_probes:
                if not dst_rec.alert_emitted:
                    dst_rec.alert_emitted = True
                    probed_list = sorted(list(dst_rec.ports))
                    return PortScanCorrelationResult(
                        is_port_scan=True,
                        source_ip=clean_src,
                        target_ip=clean_dst,
                        unique_ports_count=target_unique_ports,
                        probed_ports=probed_list,
                        total_probes=dst_rec.probe_count,
                        window_seconds=round(dst_rec.last_seen - dst_rec.first_seen, 2),
                        scan_type="VERTICAL",
                        description=(
                            f"Multi-flow vertical port scan detected: source {clean_src} probed {target_unique_ports} "
                            f"distinct ports on target {clean_dst} within {self.window_seconds:.0f}s window."
                        ),
                    )

            # Check Distributed / Multi-Target Scan: probing multiple distinct ports across destinations
            total_unique_ports = len(src_state.all_unique_ports)
            if total_unique_ports >= self.min_unique_ports and src_state.total_probes >= self.min_probes:
                if not src_state.alert_emitted:
                    src_state.alert_emitted = True
                    probed_list = sorted(list(src_state.all_unique_ports))
                    return PortScanCorrelationResult(
                        is_port_scan=True,
                        source_ip=clean_src,
                        target_ip=f"{len(src_state.destinations)} targets (subnet scan)",
                        unique_ports_count=total_unique_ports,
                        probed_ports=probed_list,
                        total_probes=src_state.total_probes,
                        window_seconds=round(src_state.last_seen - src_state.first_seen, 2),
                        scan_type="DISTRIBUTED",
                        description=(
                            f"Multi-flow horizontal/subnet port scan detected: source {clean_src} probed {total_unique_ports} "
                            f"distinct ports across {len(src_state.destinations)} destination(s) within {self.window_seconds:.0f}s window."
                        ),
                    )

            return None

    def _prune_stale(self, current_time: float) -> int:
        """Prune all expired sources older than window_seconds."""
        cutoff = current_time - self.window_seconds
        stale_keys = []
        for src_ip, state in self._sources.items():
            if state.last_seen < cutoff:
                stale_keys.append(src_ip)
            else:
                state.purge_stale_destinations(cutoff)
        for k in stale_keys:
            del self._sources[k]
        return len(stale_keys)
