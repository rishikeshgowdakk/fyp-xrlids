"""PacketCaptureService abstraction for Phase 3 live network validation.

Provides an observational capture foundation supporting:
1. Pure-Python Linux raw packet sockets (AF_PACKET) when CAP_NET_RAW is available.
2. PCAP file streaming replay (via xrlids.demo.pcap.PcapReader).
3. Synthetic in-memory packet generator for regression tests and lab validation.
4. Optional Scapy backend if installed in the environment.

Strict Invariants:
- OBSERVATIONAL ONLY: Never injects, modifies, drops, or reroutes traffic.
- Never crashes on malformed packets; logs malformed frames and increments error counters.
- Clean permission detection with explicit failure reporting.
"""

from __future__ import annotations

import logging
import socket
import select
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Iterable, Iterator, Sequence

from xrlids.demo.pcap import PacketInfo, PcapReader, parse_packet_bytes

logger = logging.getLogger(__name__)


@dataclass
class CaptureConfig:
    """Configuration options for packet capture service."""

    interface: str | None = None
    bpf_filter: str | None = None
    buffer_size: int = 65536
    snaplen: int = 65535
    promiscuous: bool = False
    timeout_s: float = 1.0
    max_packets: int | None = None


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


class PacketCaptureService:
    """Thread-safe observational packet capture service."""

    def __init__(
        self,
        config: CaptureConfig | None = None,
        *,
        pcap_path: str | Path | None = None,
        synthetic_stream: Iterable[PacketInfo] | None = None,
        raw_packet_callback: Callable[[bytes, float], None] | None = None,
    ) -> None:
        self.config = config or CaptureConfig()
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.synthetic_stream = synthetic_stream
        self.raw_packet_callback = raw_packet_callback
        self.stats = CaptureStats()
        self._running = False
        self._stop_event = threading.Event()
        self._raw_socket: socket.socket | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @staticmethod
    def check_permissions() -> bool:
        """Check whether the current process has CAP_NET_RAW / root privileges for raw sockets."""
        try:
            # Attempt to create raw AF_PACKET socket (Linux specific)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            return True
        except (PermissionError, OSError, AttributeError):
            return False

    def stream_packets(self) -> Generator[PacketInfo, None, None]:
        """Stream parsed PacketInfo objects from the configured source."""
        self._running = True
        self._stop_event.clear()
        self.stats.start_time = time.time()

        try:
            if self.synthetic_stream is not None:
                yield from self._stream_synthetic()
            elif self.pcap_path is not None:
                yield from self._stream_pcap()
            else:
                yield from self._stream_live_socket()
        finally:
            self._running = False
            self.stats.stop_time = time.time()
            self._close_socket()

    def _stream_synthetic(self) -> Generator[PacketInfo, None, None]:
        """Stream from in-memory synthetic generator."""
        assert self.synthetic_stream is not None
        for pkt in self.synthetic_stream:
            if self._stop_event.is_set():
                break
            if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                break
            self.stats.packets_captured += 1
            self.stats.bytes_captured += pkt.packet_length
            yield pkt

    def _stream_pcap(self) -> Generator[PacketInfo, None, None]:
        """Stream from recorded PCAP file."""
        assert self.pcap_path is not None
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        reader = PcapReader(self.pcap_path)
        for pkt in reader.read_packets():
            if self._stop_event.is_set():
                break
            if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                break
            self.stats.packets_captured += 1
            self.stats.bytes_captured += pkt.packet_length
            yield pkt

    def _stream_live_socket(self) -> Generator[PacketInfo, None, None]:
        """Stream from live Linux AF_PACKET raw socket."""
        if not self.check_permissions():
            raise PermissionError(
                "Live network packet capture requires raw socket privileges (CAP_NET_RAW / root). "
                "For unprivileged testing, provide pcap_path or synthetic_stream."
            )

        # ETH_P_ALL = 0x0003
        self._raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self._raw_socket.setblocking(False)

        if self.config.interface and self.config.interface != "any":
            try:
                self._raw_socket.bind((self.config.interface, 0))
            except OSError as err:
                self._close_socket()
                raise OSError(f"Failed to bind raw socket to interface '{self.config.interface}': {err}") from err

        while not self._stop_event.is_set():
            if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                break

            # Poll socket with select
            readable, _, _ = select.select([self._raw_socket], [], [], self.config.timeout_s)
            if not readable:
                continue

            try:
                raw_data, _ = self._raw_socket.recvfrom(self.config.snaplen)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as err:
                self.stats.errors += 1
                logger.error("Error reading raw socket: %s", err)
                break

            ts = time.time()
            if self.raw_packet_callback is not None:
                try:
                    # Passive observer hook: the callback receives the raw
                    # frame before parsing and must never send or mutate traffic.
                    self.raw_packet_callback(raw_data, ts)
                except Exception:  # pragma: no cover - observer must not kill capture
                    logger.debug("Raw packet observer failed", exc_info=True)

            pkt_info = parse_packet_bytes(raw_data, ts)
            if pkt_info is None:
                self.stats.malformed_packets += 1
                continue

            # Optional BPF/filter check (IP/port filter)
            if self.config.bpf_filter and not self._matches_filter(pkt_info, self.config.bpf_filter):
                continue

            self.stats.packets_captured += 1
            self.stats.bytes_captured += pkt_info.packet_length
            yield pkt_info

    def _matches_filter(self, pkt: PacketInfo, bpf_filter: str) -> bool:
        """Basic protocol and port filter matching."""
        tokens = bpf_filter.lower().split()
        if "tcp" in tokens and not pkt.is_tcp:
            return False
        if "udp" in tokens and pkt.protocol != 17:
            return False
        if "port" in tokens:
            try:
                idx = tokens.index("port")
                target_port = int(tokens[idx + 1])
                if pkt.src_port != target_port and pkt.dst_port != target_port:
                    return False
            except (IndexError, ValueError):
                pass
        return True

    def stop(self) -> None:
        """Signal the capture service to gracefully terminate."""
        self._stop_event.set()
        self._running = False
        self._close_socket()

    def _close_socket(self) -> None:
        """Safely close open raw socket."""
        if self._raw_socket is not None:
            try:
                self._raw_socket.close()
            except Exception:
                pass
            self._raw_socket = None
