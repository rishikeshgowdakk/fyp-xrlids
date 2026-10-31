"""Unix Domain Socket IPC Receiver for Network Namespace Packet Capture.

Hosts the Unix domain socket server on the host application side, receiving streamed
packet JSON records from `NetnsCaptureWorker` running inside the isolated victim namespace,
reconstructing canonical `PacketInfo` objects, and queueing them for the flow builder.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
from typing import Any

from xrlids.demo.pcap import PacketInfo
from xrlids.utils.logging_utils import get_logger

logger = get_logger("xrlids.capture.ipc")

DEFAULT_SOCKET_PATH = "/tmp/xrlids_capture.sock"


class NetnsPacketReceiver:
    """Unix Domain Socket Server receiving captured packet streams from victim netns."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        queue_size: int = 10000,
    ) -> None:
        self.socket_path = socket_path
        self.queue_size = queue_size
        self._queue: queue.Queue[PacketInfo] = queue.Queue(maxsize=queue_size)

        self._server_sock: socket.socket | None = None
        self._client_sock: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.is_running = False
        self.is_worker_connected = False
        self.worker_info: dict[str, Any] = {}

        self.packets_captured = 0
        self.bytes_captured = 0
        self.icmp_packets = 0
        self.malformed_packets = 0
        self.start_time: float = 0.0
        self.stop_time: float = 0.0

    def start(self) -> tuple[bool, str]:
        """Bind Unix domain socket and start listening in background thread."""
        with self._lock:
            if self.is_running:
                return True, "Receiver already listening."

            # Remove stale socket file if present
            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except Exception as exc:
                    return False, f"Could not remove stale socket {self.socket_path}: {exc}"

            try:
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.bind(self.socket_path)
                # Allow any local user/root to connect
                os.chmod(self.socket_path, 0o666)
                server.listen(1)
                server.settimeout(0.5)
                self._server_sock = server
            except Exception as exc:
                logger.error("Failed to bind IPC socket at %s: %s", self.socket_path, exc)
                return False, f"Failed to bind IPC socket: {exc}"

            self._stop_event.clear()
            self.is_running = True
            self.start_time = time.time()
            self.stop_time = 0.0

            self._listener_thread = threading.Thread(
                target=self._accept_and_read_loop,
                daemon=True,
                name="NetnsIpcReceiver",
            )
            self._listener_thread.start()
            logger.info("NetnsPacketReceiver listening on %s", self.socket_path)
            return True, f"IPC Receiver listening on {self.socket_path}"

    def _accept_and_read_loop(self) -> None:
        """Accepts client connection from netns worker and streams packet records."""
        assert self._server_sock is not None

        while not self._stop_event.is_set():
            if not self._client_sock:
                try:
                    client, _ = self._server_sock.accept()
                    client.settimeout(0.5)
                    with self._lock:
                        self._client_sock = client
                        self.is_worker_connected = True
                    logger.info("Worker connected to IPC socket %s", self.socket_path)
                except socket.timeout:
                    continue
                except Exception as exc:
                    if not self._stop_event.is_set():
                        logger.debug("Socket accept exception: %s", exc)
                    continue

            # Read stream lines from client
            buffer = ""
            while not self._stop_event.is_set() and self._client_sock:
                try:
                    data = self._client_sock.recv(4096)
                    if not data:
                        logger.info("Worker disconnected from IPC socket.")
                        with self._lock:
                            self._client_sock = None
                            self.is_worker_connected = False
                        break

                    buffer += data.decode("utf-8", errors="replace")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            self._handle_raw_line(line)
                except socket.timeout:
                    continue
                except Exception as exc:
                    if not self._stop_event.is_set():
                        logger.debug("Socket recv error: %s", exc)
                    with self._lock:
                        self._client_sock = None
                        self.is_worker_connected = False
                    break

    def _handle_raw_line(self, line: str) -> None:
        """Parse incoming JSON line from capture worker."""
        try:
            msg = json.loads(line)
            if msg.get("_type") == "WORKER_READY":
                with self._lock:
                    self.worker_info = msg
                    self.is_worker_connected = True
                logger.info("Received WORKER_READY handshake: PID=%s on %s", msg.get("pid"), msg.get("interface"))
                return

            pkt = PacketInfo(
                timestamp=float(msg["timestamp"]),
                src_ip=str(msg["src_ip"]),
                dst_ip=str(msg["dst_ip"]),
                src_port=int(msg.get("src_port", 0)),
                dst_port=int(msg.get("dst_port", 0)),
                protocol=int(msg.get("protocol", 1)),
                packet_length=int(msg.get("packet_length", 84)),
                is_tcp=bool(msg.get("is_tcp", False)),
                syn=bool(msg.get("syn", False)),
                ack=bool(msg.get("ack", False)),
                rst=bool(msg.get("rst", False)),
                fin=bool(msg.get("fin", False)),
                psh=bool(msg.get("psh", False)),
                urg=bool(msg.get("urg", False)),
                raw_flags=int(msg.get("raw_flags", 0)),
            )

            with self._lock:
                self.packets_captured += 1
                self.bytes_captured += pkt.packet_length
                if pkt.protocol == 1:
                    self.icmp_packets += 1

            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                pass  # Bounded queue protects memory
        except Exception as exc:
            with self._lock:
                self.malformed_packets += 1
            logger.debug("Malformed IPC line: %s (%s)", line[:60], exc)

    def get_packet(self, timeout: float = 0.2) -> PacketInfo | None:
        """Retrieve next captured packet from queue."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def stop(self, timeout_s: float = 2.0) -> None:
        """Signal receiver to stop, close sockets, and clean up socket file."""
        with self._lock:
            self._stop_event.set()
            self.is_running = False
            self.is_worker_connected = False
            self.stop_time = time.time()

        if self._client_sock:
            try:
                self._client_sock.close()
            except Exception:
                pass
            self._client_sock = None

        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=timeout_s)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

        logger.info(
            "NetnsPacketReceiver stopped. Captured %d packets (%d ICMP).",
            self.packets_captured,
            self.icmp_packets,
        )

    def get_stats(self) -> dict[str, Any]:
        """Observability telemetry."""
        now = time.time()
        dur = 0.0
        if self.start_time > 0:
            end = self.stop_time if self.stop_time > 0 else now
            dur = max(0.0, end - self.start_time)
        pps = round(self.packets_captured / dur, 2) if dur > 0 else 0.0

        return {
            "is_running": self.is_running,
            "is_connected": self.is_worker_connected,
            "worker_info": dict(self.worker_info),
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "icmp_packets": self.icmp_packets,
            "malformed_packets": self.malformed_packets,
            "queue_size": self._queue.qsize(),
            "duration_s": round(dur, 2),
            "packets_per_sec": pps,
        }
