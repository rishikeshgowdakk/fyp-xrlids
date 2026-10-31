"""Live Packet Capture and Flow Ingestion Manager for XRL-IDARS (Phase 2).

Provides thread-safe lifecycle coordination:
- Manages ScapyCaptureService with explicit start / stop lifecycle
- Consumes raw packets from bounded queue
- Feeds CanonicalFlowBuilder (bidirectional 5-tuple, FIN/RST emission, idle timeout)
- Feeds completed flows into ActiveInferencePipeline
- Emits security events to EventManager
- Provides real-time metrics (captured, dropped, malformed, active flows, completed flows, threats, errors)
- Guarantees zero dangling threads and graceful stop even if no packets arrive
- Explicitly handles permission boundaries (CAP_NET_RAW / root) and reports BLOCKED status
"""

from __future__ import annotations

import logging
from pathlib import Path
import threading
import time
from typing import Any

from xrlids.capture.netns_ipc import NetnsPacketReceiver
from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService, get_if_list
from xrlids.demo.privileged_runner import run_helper
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlow, CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class LiveCaptureManager:
    """Coordinates live Scapy packet capture, flow assembly, and pipeline inference."""

    def __init__(
        self,
        pipeline: ActiveInferencePipeline | None = None,
        event_manager: EventManager | None = None,
        idle_timeout_s: float = 120.0,
    ) -> None:
        self.event_manager = event_manager or EventManager()
        self.pipeline = pipeline or ActiveInferencePipeline(event_manager=self.event_manager)
        self.idle_timeout_s = idle_timeout_s

        self.service: ScapyCaptureService | None = None
        self.receiver: NetnsPacketReceiver | None = None
        self.capture_mode: str = "INTERFACE"  # "INTERFACE" or "NETNS"
        self.flow_builder = CanonicalFlowBuilder(idle_timeout_s=self.idle_timeout_s, icmp_idle_timeout_s=2.0)

        self._consumer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.status = "IDLE"  # IDLE, RUNNING, STOPPED, BLOCKED
        self.interface: str = "lo"
        self.bpf_filter: str = "ip"
        self.last_error: str | None = None

        self.completed_flows: list[CanonicalFlow] = []
        self.threats_detected: int = 0
        self.start_time: float = 0.0
        self.stop_time: float = 0.0

    @property
    def is_running(self) -> bool:
        return self.status == "RUNNING" and self._consumer_thread is not None and self._consumer_thread.is_alive()

    @staticmethod
    def check_permissions() -> tuple[bool, str]:
        """Check raw packet capture permissions."""
        return ScapyCaptureService.check_raw_capture_permission()

    @staticmethod
    def get_available_interfaces() -> list[str]:
        """List detectable network interfaces."""
        ifaces = ScapyCaptureService.list_interfaces()
        if not ifaces:
            ifaces = ["lo", "eth0", "wlan0"]
        return ifaces

    def start(
        self,
        interface: str = "lo",
        bpf_filter: str = "ip",
        max_packets: int | None = None,
        allow_virtual_fallback: bool = False,
    ) -> tuple[bool, str]:
        """Start live interface capture and background flow consumption."""
        with self._lock:
            if self.is_running:
                return False, "Capture worker is already running."

            self.interface = interface
            self.bpf_filter = bpf_filter
            self.last_error = None

            # Verify permissions first
            has_perm, perm_msg = self.check_permissions()
            if not has_perm and not allow_virtual_fallback:
                self.status = "BLOCKED"
                self.last_error = f"Permission Denied: {perm_msg}"
                logger.warning("Live capture BLOCKED on %s: %s", interface, perm_msg)
                return False, self.last_error

            # Initialize capture service
            cfg = ScapyCaptureConfig(
                interface=interface if has_perm else None,
                bpf_filter=bpf_filter,
                max_packets=max_packets,
                queue_size=10000,
            )
            self.service = ScapyCaptureService(cfg)
            self.flow_builder = CanonicalFlowBuilder(idle_timeout_s=self.idle_timeout_s)
            self._stop_event.clear()
            self.completed_flows.clear()
            self.threats_detected = 0
            self.start_time = time.time()
            self.stop_time = 0.0

            if has_perm:
                try:
                    self.service.start()
                except Exception as exc:
                    self.status = "BLOCKED"
                    self.last_error = f"Failed to open interface {interface}: {exc}"
                    logger.error("Live capture service start failed: %s", exc)
                    return False, self.last_error

                # Give worker 0.15s to verify socket binding
                time.sleep(0.15)
                if self.service.last_error:
                    self.status = "BLOCKED"
                    self.last_error = f"Socket Error on {interface}: {self.service.last_error}"
                    self.service.stop()
                    return False, self.last_error
            else:
                logger.info("Starting live capture worker in Lab Virtual Tap mode on interface %s (Unprivileged sandbox)", interface)

            # Start background consumer thread
            self.status = "RUNNING"
            self._consumer_thread = threading.Thread(
                target=self._consumer_loop,
                daemon=True,
                name=f"LiveCaptureConsumer-{interface}",
            )
            self._consumer_thread.start()
            mode_desc = "promiscuous raw capture" if has_perm else "lab virtual tap"
            logger.info("Live capture worker started on interface %s (%s)", interface, mode_desc)
            return True, f"Capture active on {interface} ({mode_desc})"

    def start_netns_capture(
        self,
        netns: str = "xrlids_vic_01",
        interface: str = "veth_xrl_vic",
        socket_path: str = "/tmp/xrlids_capture.sock",
    ) -> tuple[bool, str]:
        """Start genuine packet capture inside the isolated victim network namespace."""
        with self._lock:
            if self.is_running:
                return False, "Capture worker is already running."

            self.interface = interface
            self.capture_mode = "NETNS"
            self.last_error = None

            # 1. Start host-side IPC receiver
            self.receiver = NetnsPacketReceiver(socket_path=socket_path)
            ok, msg = self.receiver.start()
            if not ok:
                self.status = "BLOCKED"
                self.last_error = f"Failed to start IPC receiver: {msg}"
                return False, self.last_error

            # 2. Invoke privileged helper to start victim namespace capture worker
            helper_ok, helper_data, helper_err = run_helper("start-capture", ["--socket", socket_path])
            if not helper_ok:
                self.receiver.stop()
                self.receiver = None
                self.status = "BLOCKED"
                self.last_error = f"Failed to start netns capture worker: {helper_err}"
                return False, self.last_error

            self.flow_builder = CanonicalFlowBuilder(idle_timeout_s=self.idle_timeout_s, icmp_idle_timeout_s=2.0)
            self._stop_event.clear()
            self.completed_flows.clear()
            self.threats_detected = 0
            self.start_time = time.time()
            self.stop_time = 0.0
            self.status = "RUNNING"

            # 3. Start background consumer thread reading from IPC receiver
            self._consumer_thread = threading.Thread(
                target=self._netns_consumer_loop,
                daemon=True,
                name=f"NetnsCaptureConsumer-{netns}",
            )
            self._consumer_thread.start()
            logger.info("Real netns capture started inside %s on %s (IPC: %s)", netns, interface, socket_path)
            return True, f"Real packet capture running inside {netns} on {interface}."

    def stop(self, timeout_s: float = 2.5) -> dict[str, Any]:
        """Signal capture to stop, flush remaining flows, and wait for threads."""
        with self._lock:
            self._stop_event.set()

        if self.capture_mode == "NETNS":
            try:
                run_helper("stop-capture")
            except Exception as exc:
                logger.debug("stop-capture helper error: %s", exc)
            if self.receiver:
                self.receiver.stop(timeout_s=timeout_s)

        if self.service:
            self.service.stop(timeout_s=timeout_s)

        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=timeout_s)

        # Flush any remaining unclosed flows
        flushed = self.flow_builder.flush_all()
        source_label = "REAL LIVE CAPTURE" if self.capture_mode == "NETNS" else "LIVE"
        for f in flushed:
            self.completed_flows.append(f)
            try:
                res = self.pipeline.process_flow(f, source_mode=source_label)
                if res.hybrid.is_attack or res.inference.attack_score >= 0.50:
                    self.threats_detected += 1
            except Exception as e:
                logger.error("Error evaluating flushed flow: %s", e)

        with self._lock:
            self.status = "STOPPED"
            self.stop_time = time.time()
            logger.info(
                "Live capture worker stopped on %s. Completed %d flows.",
                self.interface,
                len(self.completed_flows),
            )
            return self.get_stats()

    def _netns_consumer_loop(self) -> None:
        """Continuously pulls packets from NetnsPacketReceiver and constructs flows."""
        assert self.receiver is not None
        last_timeout_check = time.time()

        while not self._stop_event.is_set():
            pkt = self.receiver.get_packet(timeout=0.2)
            if pkt is not None:
                try:
                    newly_completed = self.flow_builder.process_packet(pkt)
                    for flow in newly_completed:
                        self.completed_flows.append(flow)
                        res = self.pipeline.process_flow(flow, source_mode="REAL LIVE CAPTURE")
                        if res.hybrid.is_attack or res.inference.attack_score >= 0.50:
                            self.threats_detected += 1
                except Exception as exc:
                    logger.error("Error processing packet in netns consumer: %s", exc)

            # Periodically check timeouts for idle flows (e.g. prompt ICMP flow expiration)
            now = time.time()
            if now - last_timeout_check >= 0.5:
                last_timeout_check = now
                try:
                    expired_flows = self.flow_builder.check_timeouts(now)
                    for flow in expired_flows:
                        self.completed_flows.append(flow)
                        res = self.pipeline.process_flow(flow, source_mode="REAL LIVE CAPTURE")
                        if res.hybrid.is_attack or res.inference.attack_score >= 0.50:
                            self.threats_detected += 1
                except Exception as exc:
                    logger.error("Error evaluating timed-out flows: %s", exc)

        with self._lock:
            if self.status == "RUNNING":
                self.status = "STOPPED"
                self.stop_time = time.time()

    def _consumer_loop(self) -> None:
        """Continuously pulls packets from Scapy service queue and constructs flows."""
        assert self.service is not None

        while not self._stop_event.is_set():
            # Check if capture service encountered fatal runtime socket error
            if self.service.last_error:
                with self._lock:
                    self.status = "BLOCKED"
                    self.last_error = self.service.last_error
                break

            # Poll with timeout to ensure stop_event is checked regularly
            pkt = self.service.get_packet(timeout=0.2)
            if pkt is not None:
                try:
                    newly_completed = self.flow_builder.process_packet(pkt)
                    for flow in newly_completed:
                        self.completed_flows.append(flow)
                        res = self.pipeline.process_flow(flow, source_mode="LIVE")
                        if res.hybrid.is_attack or res.inference.attack_score >= 0.50:
                            self.threats_detected += 1
                except Exception as exc:
                    logger.error("Error in live flow consumer: %s", exc)

        with self._lock:
            if self.status == "RUNNING":
                self.status = "STOPPED"
                self.stop_time = time.time()

    def get_stats(self) -> dict[str, Any]:
        """Return real-time observability counters."""
        now = time.time()
        dur = 0.0
        if self.start_time > 0:
            end = self.stop_time if self.stop_time > 0 else now
            dur = max(0.0, end - self.start_time)

        if self.capture_mode == "NETNS" and self.receiver:
            rcv_stats = self.receiver.get_stats()
            pkts = rcv_stats.get("packets_captured", 0)
            pps = round(pkts / dur, 2) if dur > 0 else 0.0
            return {
                "status": self.status,
                "capture_mode": "NETNS",
                "source_mode": "REAL LIVE CAPTURE",
                "interface": self.interface,
                "netns": "xrlids_vic_01",
                "is_connected": rcv_stats.get("is_connected", False),
                "packets_captured": pkts,
                "bytes_captured": rcv_stats.get("bytes_captured", 0),
                "icmp_packets": rcv_stats.get("icmp_packets", 0),
                "malformed_packets": rcv_stats.get("malformed_packets", 0),
                "packets_dropped": 0,
                "capture_errors": 0,
                "active_flows": len(self.flow_builder.active_flows),
                "completed_flows": len(self.completed_flows),
                "threats_detected": self.threats_detected,
                "duration_s": round(dur, 2),
                "packets_per_sec": pps,
                "last_error": self.last_error,
            }

        service_stats = self.service.stats.to_dict() if self.service else {}
        pkts = service_stats.get("packets_captured", 0)
        pps = round(pkts / dur, 2) if dur > 0 else 0.0

        return {
            "status": self.status,
            "capture_mode": "INTERFACE",
            "source_mode": "LIVE",
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "packets_captured": pkts,
            "bytes_captured": service_stats.get("bytes_captured", 0),
            "packets_dropped": service_stats.get("packets_dropped", 0),
            "malformed_packets": service_stats.get("malformed_packets", 0),
            "capture_errors": service_stats.get("errors", 0),
            "active_flows": len(self.flow_builder.active_flows),
            "completed_flows": len(self.completed_flows),
            "threats_detected": self.threats_detected,
            "duration_s": round(dur, 2),
            "packets_per_sec": pps,
            "last_error": self.last_error,
        }

    get_status = get_stats
