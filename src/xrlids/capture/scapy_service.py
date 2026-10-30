"""Unified Scapy Packet Capture and PCAP Replay Service for XRL-IDARS.

Provides thread-safe, bounded-queue packet capture supporting:
1. Live network interface sniffing via Scapy (when privileged).
2. PCAP file reading and pacing replay.
3. Accurate packet parsing for IPv4, TCP (flags: SYN, ACK, FIN, RST, PSH, URG), and UDP.
4. Bounded queues preventing memory exhaustion under traffic spikes.
5. Observability metrics: packets/bytes captured, dropped frames, error counters, throughput.
6. Direct and streaming generators (replay_pcap, stream_packets).
7. Permission checking and graceful fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import queue
import threading
import time
from typing import Any, Callable, Generator, Iterable, Iterator, Sequence

try:
    from scapy.all import IP, TCP, UDP, Ether, get_if_list, sniff
    from scapy.utils import PcapReader as ScapyPcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    get_if_list = lambda: []  # noqa: E731

from xrlids.demo.pcap import PacketInfo, PcapReader as PurePythonPcapReader, parse_packet_bytes
from xrlids.utils.logging_utils import get_logger

logger = get_logger("xrlids.capture.scapy")


class CapturePermissionError(PermissionError):
    """Raised when insufficient operating system privileges exist for raw packet capture."""


@dataclass
class ScapyCaptureConfig:
    """Configuration options for Scapy capture service."""

    interface: str | None = None
    bpf_filter: str | None = None
    pcap_path: str | Path | None = None
    max_packets: int | None = None
    queue_size: int = 10000
    timeout_s: float = 1.0
    promiscuous: bool = False
    pcap_replay_speed_factor: float = 0.0  # 0.0 = instant/fastest; 1.0 = real-time pacing


@dataclass
class CaptureStats:
    """Runtime observability counters for packet capture."""

    packets_captured: int = 0
    bytes_captured: int = 0
    packets_dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    malformed_packets: int = 0
    errors: int = 0
    start_time: float = 0.0
    stop_time: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.start_time <= 0:
            return 0.0
        end = self.stop_time if self.stop_time > 0 else time.time()
        return max(0.0, end - self.start_time)

    @property
    def packets_per_second(self) -> float:
        dur = self.duration_s
        return float(self.packets_captured / dur) if dur > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "packets_dropped": self.packets_dropped,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "malformed_packets": self.malformed_packets,
            "errors": self.errors,
            "duration_s": round(self.duration_s, 4),
            "packets_per_second": round(self.packets_per_second, 2),
        }


def scapy_packet_to_packet_info(scapy_pkt: Any) -> PacketInfo | None:
    """Convert a Scapy packet object to canonical PacketInfo.

    Handles Scapy Ether/IP/TCP/UDP layers safely without throwing on non-IP frames.
    Extracts only network/transport headers; zero payload retention.
    """
    try:
        ts = float(getattr(scapy_pkt, "time", time.time()))
        pkt_len = int(len(scapy_pkt))

        # Check for IP layer
        if not hasattr(scapy_pkt, "haslayer") or not scapy_pkt.haslayer("IP"):
            # Could be raw frame or IPv6; extract raw bytes if available
            raw = bytes(scapy_pkt)
            return parse_packet_bytes(raw, ts)

        ip = scapy_pkt["IP"]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        proto = int(ip.proto)

        src_port = 0
        dst_port = 0
        is_tcp = False
        syn = False
        ack = False
        rst = False
        fin = False
        psh = False
        urg = False
        raw_flags = 0

        if scapy_pkt.haslayer("TCP"):
            tcp = scapy_pkt["TCP"]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            is_tcp = True
            flags = str(tcp.flags).upper()
            syn = "S" in flags
            ack = "A" in flags
            rst = "R" in flags
            fin = "F" in flags
            psh = "P" in flags
            urg = "U" in flags
            try:
                raw_flags = int(getattr(tcp.flags, "value", tcp.flags))
            except Exception:
                raw_flags = 0

        elif scapy_pkt.haslayer("UDP"):
            udp = scapy_pkt["UDP"]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)

        return PacketInfo(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            packet_length=pkt_len,
            is_tcp=is_tcp,
            syn=syn,
            ack=ack,
            rst=rst,
            fin=fin,
            psh=psh,
            urg=urg,
            raw_flags=raw_flags,
        )
    except Exception as exc:
        logger.debug("Failed to convert Scapy packet: %s", exc)
        return None


class ScapyCaptureService:
    """Dedicated background packet capture and replay service using Scapy.

    Runs in a dedicated thread and communicates with consumers via a bounded queue.
    Also provides direct streaming generators (replay_pcap) for interactive inspection.
    """

    def __init__(self, config: ScapyCaptureConfig | None = None) -> None:
        self.config = config or ScapyCaptureConfig()
        self.stats = CaptureStats()
        self.last_error: str | None = None
        self.last_exception: Exception | None = None
        self._queue: queue.Queue[PacketInfo | None] = queue.Queue(maxsize=self.config.queue_size)
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None
        self._sniff_thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    @staticmethod
    def list_interfaces() -> list[str]:
        """Return list of network interfaces available on the system."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return list(get_if_list())
        except Exception as e:
            logger.warning("Could not list interfaces via Scapy: %s", e)
            return []

    @staticmethod
    def check_permissions() -> bool:
        """Check whether the process has raw socket permissions to sniff interfaces."""
        if os.name != "posix":
            return False
        # Root check or CAP_NET_RAW socket test
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
        try:
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            return True
        except (PermissionError, OSError, AttributeError):
            return False

    @staticmethod
    def check_raw_capture_permission() -> tuple[bool, str]:
        """Check if current process has privileges to open raw packet capture sockets."""
        if os.name != "posix":
            return True, "Non-POSIX environment"
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True, "Root privileges verified (euid=0)"
        try:
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            s.close()
            return True, "Raw socket creation permitted (CAP_NET_RAW capability present)"
        except PermissionError:
            return False, "Insufficient privileges for raw packet capture. Run as root or grant CAP_NET_RAW."
        except Exception as err:
            return False, f"Raw socket check failed: {err}"

    def verify_permissions(self) -> tuple[bool, str]:
        """Check raw socket permissions on the host."""
        return self.check_raw_capture_permission()

    def start(self) -> None:
        """Start background capture worker thread."""
        with self._lock:
            if self._running:
                logger.warning("ScapyCaptureService is already running.")
                return
            self._stop_event.clear()
            self._running = True
            self.stats = CaptureStats(start_time=time.time())
            self._worker_thread = threading.Thread(target=self._run_capture, daemon=True, name="ScapyCaptureWorker")
            self._worker_thread.start()
            logger.info("ScapyCaptureService started (interface=%s, pcap=%s)", self.config.interface, self.config.pcap_path)

    def stop(self, timeout_s: float = 3.0) -> None:
        """Signal capture thread to stop and wait for termination."""
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout_s)

        with self._lock:
            self._running = False
            self.stats.stop_time = time.time()
            logger.info("ScapyCaptureService stopped. Captured %d packets.", self.stats.packets_captured)

    def get_packet(self, timeout: float = 0.5) -> PacketInfo | None:
        """Retrieve the next parsed packet from the bounded queue."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def stream_packets(self) -> Generator[PacketInfo, None, None]:
        """Generator yielding PacketInfo objects until stopped or queue exhausted."""
        while self._running or not self._queue.empty():
            pkt = self.get_packet(timeout=0.2)
            if pkt is not None:
                yield pkt
            elif self._stop_event.is_set() and self._queue.empty():
                break

    def _enqueue_packet(self, pkt: PacketInfo) -> bool:
        """Put packet into bounded queue; drop if full and increment drop counter."""
        try:
            self._queue.put_nowait(pkt)
            self.stats.packets_captured += 1
            self.stats.bytes_captured += pkt.packet_length
            if pkt.is_tcp:
                self.stats.tcp_packets += 1
            else:
                self.stats.udp_packets += 1
            return True
        except queue.Full:
            self.stats.packets_dropped += 1
            return False

    def inject_scapy_packet(self, scapy_pkt: Any) -> bool:
        """Inject a Scapy packet into capture pipeline (used in isolated lab simulator)."""
        pkt_info = scapy_packet_to_packet_info(scapy_pkt)
        if pkt_info is not None:
            return self._enqueue_packet(pkt_info)
        self.stats.malformed_packets += 1
        return False

    def inject_packet_info(self, pkt: PacketInfo) -> bool:
        """Inject parsed PacketInfo directly into capture queue."""
        return self._enqueue_packet(pkt)

    def replay_pcap(
        self,
        pcap_path: str | Path,
        delay_factor: float = 0.0,
        max_packets: int | None = None,
    ) -> Generator[PacketInfo, None, None]:
        """Stream packets from a PCAP file directly as a generator with zero payload retention."""
        path = Path(pcap_path)
        if not path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        self.stats.start_time = time.time()
        prev_pkt_time: float | None = None

        if SCAPY_AVAILABLE:
            try:
                reader = ScapyPcapReader(str(path))
                count = 0
                for raw_pkt in reader:
                    info = scapy_packet_to_packet_info(raw_pkt)
                    if info is not None:
                        count += 1
                        self.stats.packets_captured += 1
                        self.stats.bytes_captured += info.packet_length
                        if info.is_tcp:
                            self.stats.tcp_packets += 1
                        else:
                            self.stats.udp_packets += 1

                        if delay_factor > 0.0 and prev_pkt_time is not None:
                            delta = max(0.0, info.timestamp - prev_pkt_time) * delay_factor
                            if delta > 0.0:
                                time.sleep(min(delta, 1.0))
                        prev_pkt_time = info.timestamp

                        yield info
                        if max_packets is not None and count >= max_packets:
                            break
                reader.close()
                self.stats.stop_time = time.time()
                return
            except Exception as e:
                logger.warning("Scapy PcapReader encountered error, falling back to pure-Python parser: %s", e)

        # Fallback to pure-Python PcapReader
        pure_reader = PurePythonPcapReader(path)
        count = 0
        for info in pure_reader.read_packets():
            count += 1
            self.stats.packets_captured += 1
            self.stats.bytes_captured += info.packet_length
            if info.is_tcp:
                self.stats.tcp_packets += 1
            else:
                self.stats.udp_packets += 1

            if delay_factor > 0.0 and prev_pkt_time is not None:
                delta = max(0.0, info.timestamp - prev_pkt_time) * delay_factor
                if delta > 0.0:
                    time.sleep(min(delta, 1.0))
            prev_pkt_time = info.timestamp

            yield info
            if max_packets is not None and count >= max_packets:
                break
        self.stats.stop_time = time.time()

    def start_live_sniff(
        self,
        interface: str,
        bpf_filter: str = "ip",
        packet_callback: Callable[[PacketInfo], None] | None = None,
        count: int = 0,
        timeout: float | None = None,
    ) -> threading.Thread:
        """Start non-blocking live packet capture in a background thread."""
        has_perm, reason = self.check_raw_capture_permission()
        if not has_perm:
            raise CapturePermissionError(reason)

        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed in the environment.")

        self._stop_event.clear()
        self.stats.start_time = time.time()

        def _worker() -> None:
            def _scapy_cb(pkt: Any) -> None:
                if self._stop_event.is_set():
                    return
                info = scapy_packet_to_packet_info(pkt)
                if info is not None:
                    self.stats.packets_captured += 1
                    self.stats.bytes_captured += info.packet_length
                    if info.is_tcp:
                        self.stats.tcp_packets += 1
                    else:
                        self.stats.udp_packets += 1
                    if packet_callback is not None:
                        try:
                            packet_callback(info)
                        except Exception as e:
                            logger.error("Error in packet_callback: %s", e)
                            self.stats.errors += 1

            try:
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=_scapy_cb,
                    store=False,
                    count=count,
                    timeout=timeout,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            except Exception as e:
                logger.error("Live sniffing exception on %s: %s", interface, e)
                self.stats.errors += 1
            finally:
                self.stats.stop_time = time.time()

        thread = threading.Thread(target=_worker, name=f"ScapySniffer-{interface}", daemon=True)
        thread.start()
        self._sniff_thread = thread
        return thread

    def stop_live_sniff(self) -> None:
        """Signal live sniffing thread to terminate gracefully."""
        self._stop_event.set()
        if self._sniff_thread is not None and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2.0)
        self.stats.stop_time = time.time()

    def _run_capture(self) -> None:
        """Main worker loop dispatching to PCAP replay or live interface sniffing."""
        try:
            if self.config.pcap_path is not None:
                self._capture_from_pcap()
            else:
                self._capture_from_interface()
        except Exception as exc:
            self.stats.errors += 1
            self.last_error = str(exc)
            self.last_exception = exc
            logger.error("ScapyCaptureWorker encountered error: %s", exc)
        finally:
            with self._lock:
                self._running = False
                self.stats.stop_time = time.time()

    def _capture_from_pcap(self) -> None:
        """Stream packets from PCAP file via Scapy or fallback PcapReader into bounded queue."""
        pcap_file = Path(self.config.pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        last_ts: float | None = None
        speed = self.config.pcap_replay_speed_factor

        try:
            reader = ScapyPcapReader(str(pcap_file))
            for scapy_pkt in reader:
                if self._stop_event.is_set():
                    break
                if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                    break

                pkt_info = scapy_packet_to_packet_info(scapy_pkt)
                if pkt_info is None:
                    self.stats.malformed_packets += 1
                    continue

                if speed > 0.0 and last_ts is not None:
                    delta = (pkt_info.timestamp - last_ts) / speed
                    if 0.0 < delta < 2.0:
                        time.sleep(delta)
                last_ts = pkt_info.timestamp

                self._enqueue_packet(pkt_info)
            reader.close()
        except Exception:
            # Fallback to pure Python reader
            reader = PurePythonPcapReader(pcap_file)
            for pkt_info in reader.read_packets():
                if self._stop_event.is_set():
                    break
                if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                    break
                self._enqueue_packet(pkt_info)

    def _capture_from_interface(self) -> None:
        """Capture packets from live interface using Scapy sniff(), or virtual capture."""
        if self.config.interface in ("virtual", "isolated_lab", "veth_virtual"):
            logger.info("ScapyCaptureService running in virtual isolated capture mode.")
            while not self._stop_event.is_set():
                time.sleep(0.1)
            return

        if not self.check_permissions():
            raise PermissionError(
                "Live network capture requires root or CAP_NET_RAW permissions. "
                "Use PCAP replay mode or grant permissions to capture live network frames."
            )

        def _packet_callback(pkt: Any) -> None:
            if self._stop_event.is_set():
                return
            pkt_info = scapy_packet_to_packet_info(pkt)
            if pkt_info is not None:
                self._enqueue_packet(pkt_info)
            else:
                self.stats.malformed_packets += 1

        iface = self.config.interface if self.config.interface != "any" else None
        sniff(
            iface=iface,
            filter=self.config.bpf_filter,
            prn=_packet_callback,
            stop_filter=lambda _: self._stop_event.is_set(),
            store=False,
            count=self.config.max_packets or 0,
        )
