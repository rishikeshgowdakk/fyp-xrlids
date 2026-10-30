"""Unified Scapy Packet Capture and PCAP Replay Service (Phase 4).

Features:
1. Live sniffing via Scapy with clean permission checks (CAP_NET_RAW / root).
2. Streaming PCAP file replay with relative timing support.
3. Zero payload leakage: strips raw payloads immediately and retains only IP/TCP/UDP headers.
4. Seamless conversion to canonical PacketInfo objects feeding CanonicalFlowBuilder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Generator, Sequence

try:
    from scapy.all import IP, TCP, UDP, Ether, get_if_list, sniff
    from scapy.utils import PcapReader as ScapyPcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    get_if_list = lambda: []  # noqa: E731

from xrlids.demo.pcap import PacketInfo, PcapReader as PurePythonPcapReader
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class CapturePermissionError(PermissionError):
    """Raised when insufficient operating system privileges exist for raw packet capture."""


@dataclass
class CaptureStats:
    """Observability counters for packet capture."""

    packets_captured: int = 0
    bytes_captured: int = 0
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
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "malformed_packets": self.malformed_packets,
            "errors": self.errors,
            "duration_s": round(self.duration_s, 4),
            "packets_per_second": round(self.packets_per_second, 2),
        }


def scapy_packet_to_packet_info(pkt: Any) -> PacketInfo | None:
    """Convert a Scapy packet object into a strict PacketInfo instance.
    
    Extracts only network/transport headers. Discards payload content immediately.
    """
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    proto = int(ip_layer.proto)
    pkt_len = int(len(pkt))
    ts = float(getattr(pkt, "time", time.time()))

    is_tcp = pkt.haslayer(TCP)
    syn = ack = rst = fin = psh = urg = False
    raw_flags = 0
    src_port = dst_port = 0

    if is_tcp:
        tcp_layer = pkt[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flags = str(tcp_layer.flags)
        syn = "S" in flags
        ack = "A" in flags
        rst = "R" in flags
        fin = "F" in flags
        psh = "P" in flags
        urg = "U" in flags
        raw_flags = int(getattr(tcp_layer.flags, "value", 0))
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)

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


class ScapyCaptureService:
    """Unified packet acquisition service supporting PCAP replay and live interface sniffing."""

    def __init__(self) -> None:
        self.stats = CaptureStats()
        self._sniff_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

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
    def check_raw_capture_permission() -> tuple[bool, str]:
        """Check if current process has privileges to open raw packet capture sockets."""
        if os.name != "posix":
            return True, "Non-POSIX environment"
        if os.geteuid() == 0:
            return True, "Root privileges verified (euid=0)"
        
        # Check Linux raw socket creation
        import socket
        try:
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

    def replay_pcap(
        self,
        pcap_path: str | Path,
        delay_factor: float = 0.0,
        max_packets: int | None = None,
    ) -> Generator[PacketInfo, None, None]:
        """Stream packets from a PCAP file using Scapy or pure-Python fallback.
        
        Zero payload retention: yields lightweight PacketInfo header instances.
        """
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
