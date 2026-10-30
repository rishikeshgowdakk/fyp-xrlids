"""Scapy-based network packet capture and PCAP replay service for XRL-IDARS.

Provides thread-safe, bounded-queue packet capture supporting:
1. Live network interface sniffing via Scapy (when privileged).
2. PCAP file reading and pacing replay.
3. Accurate packet parsing for IPv4, TCP (flags: SYN, ACK, FIN, RST, PSH, URG), and UDP.
4. Bounded queues preventing memory exhaustion under traffic spikes.
5. Observability metrics: packets/bytes captured, dropped frames, error counters, throughput.
6. Graceful shutdown and clean isolation from presentation layers.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Iterable, Iterator

from xrlids.demo.pcap import PacketInfo, PcapReader, parse_packet_bytes

logger = logging.getLogger("xrlids.capture.scapy")


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

    def to_dict(self) -> dict[str, float | int]:
        return {
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "packets_dropped": self.packets_dropped,
            "malformed_packets": self.malformed_packets,
            "errors": self.errors,
            "duration_s": round(self.duration_s, 4),
            "packets_per_second": round(self.packets_per_second, 2),
        }


def scapy_packet_to_packet_info(scapy_pkt: Any) -> PacketInfo | None:
    """Convert a Scapy packet object to canonical PacketInfo.

    Handles Scapy Ether/IP/TCP/UDP layers safely without throwing on non-IP frames.
    """
    try:
        ts = float(getattr(scapy_pkt, "time", time.time()))
        pkt_len = int(len(scapy_pkt))

        # Check for IP layer
        if not scapy_pkt.haslayer("IP"):
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
            flags = tcp.flags
            # Scapy flags can be string, FlagValue, or int
            flag_str = str(flags).upper()
            syn = "S" in flag_str
            ack = "A" in flag_str
            rst = "R" in flag_str
            fin = "F" in flag_str
            psh = "P" in flag_str
            urg = "U" in flag_str
            try:
                raw_flags = int(flags)
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
    """

    def __init__(self, config: ScapyCaptureConfig | None = None) -> None:
        self.config = config or ScapyCaptureConfig()
        self.stats = CaptureStats()
        self._queue: queue.Queue[PacketInfo | None] = queue.Queue(maxsize=self.config.queue_size)
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

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
            return True
        except queue.Full:
            self.stats.packets_dropped += 1
            return False

    def _run_capture(self) -> None:
        """Main worker loop dispatching to PCAP replay or live interface sniffing."""
        try:
            if self.config.pcap_path is not None:
                self._capture_from_pcap()
            else:
                self._capture_from_interface()
        except Exception as exc:
            self.stats.errors += 1
            logger.error("ScapyCaptureWorker encounter error: %s", exc)
        finally:
            with self._lock:
                self._running = False
                self.stats.stop_time = time.time()

    def _capture_from_pcap(self) -> None:
        """Stream packets from PCAP file via Scapy or fallback PcapReader."""
        pcap_file = Path(self.config.pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        last_ts: float | None = None
        speed = self.config.pcap_replay_speed_factor

        try:
            from scapy.all import PcapReader as ScapyPcapReader
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
        except ImportError:
            # Fallback to standard library PcapReader
            reader = PcapReader(pcap_file)
            for pkt_info in reader.read_packets():
                if self._stop_event.is_set():
                    break
                if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                    break
                self._enqueue_packet(pkt_info)

    def _capture_from_interface(self) -> None:
        """Capture packets from live interface using Scapy sniff()."""
        if not self.check_permissions():
            raise PermissionError(
                "Live network capture requires root or CAP_NET_RAW permissions. "
                "Use PCAP replay mode or grant permissions to capture live network frames."
            )

        from scapy.all import sniff

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
