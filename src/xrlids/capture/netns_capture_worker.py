"""Victim Namespace Packet Capture Worker for XRL-IDARS.

Runs inside the isolated victim network namespace (e.g. `xrlids_vic_01`) on `veth_xrl_vic`.
Sniffs raw link-layer frames, parses IP and transport headers via `parse_packet_bytes`,
and forwards structured packet metadata across a Unix domain socket IPC channel to the
host XRL-IDARS application.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import time
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if os.path.join(REPO_ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from xrlids.demo.pcap import PacketInfo, parse_packet_bytes
from xrlids.utils.logging_utils import get_logger

logger = get_logger("xrlids.capture.worker")


class NetnsCaptureWorker:
    """Captures wire packets inside a network namespace and streams them over IPC."""

    def __init__(
        self,
        interface: str = "veth_xrl_vic",
        socket_path: str = "/tmp/xrlids_capture.sock",
        write_stdout: bool = False,
        max_packets: int | None = None,
    ) -> None:
        self.interface = interface
        self.socket_path = socket_path
        self.write_stdout = write_stdout
        self.max_packets = max_packets

        self.running = False
        self.ipc_sock: socket.socket | None = None
        self.capture_sock: socket.socket | None = None

        self.packets_captured = 0
        self.bytes_captured = 0
        self.icmp_packets = 0

    def connect_ipc(self, retries: int = 25, delay_s: float = 0.2) -> bool:
        """Connect to the host Unix domain socket server."""
        if not self.socket_path:
            return False

        for attempt in range(retries):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.socket_path)
                self.ipc_sock = s
                logger.info("Connected to host IPC socket at %s (attempt %d)", self.socket_path, attempt + 1)
                return True
            except (FileNotFoundError, ConnectionRefusedError) as exc:
                time.sleep(delay_s)

        logger.warning("Could not connect to IPC socket %s after %d retries.", self.socket_path, retries)
        return False

    def setup_capture_socket(self) -> socket.socket:
        """Create and bind raw packet capture socket."""
        try:
            # ETH_P_ALL = 0x0003
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            raw_sock.bind((self.interface, 0))
            raw_sock.settimeout(0.5)
            self.capture_sock = raw_sock
            logger.info("Raw AF_PACKET socket bound to interface '%s'", self.interface)
            return raw_sock
        except Exception as exc:
            logger.error("Failed to bind raw socket on '%s': %s", self.interface, exc)
            raise

    def send_packet(self, pkt: PacketInfo) -> None:
        """Serialize and transmit packet metadata to host."""
        data = {
            "timestamp": pkt.timestamp,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.protocol,
            "packet_length": pkt.packet_length,
            "is_tcp": pkt.is_tcp,
            "syn": pkt.syn,
            "ack": pkt.ack,
            "rst": pkt.rst,
            "fin": pkt.fin,
            "psh": pkt.psh,
            "urg": pkt.urg,
            "raw_flags": pkt.raw_flags,
        }
        line = json.dumps(data) + "\n"

        if self.ipc_sock:
            try:
                self.ipc_sock.sendall(line.encode("utf-8"))
            except Exception as exc:
                logger.warning("IPC send failed: %s", exc)
                self.ipc_sock = None

        if self.write_stdout:
            sys.stdout.write(line)
            sys.stdout.flush()

    def run(self) -> None:
        """Main packet capture loop."""
        self.running = True

        def _sig_handler(signum: int, frame: Any) -> None:
            logger.info("Signal %d received, stopping capture worker...", signum)
            self.running = False

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        self.connect_ipc()
        raw_sock = self.setup_capture_socket()

        # Emit ready handshake
        ready_msg = json.dumps({
            "_type": "WORKER_READY",
            "interface": self.interface,
            "pid": os.getpid(),
            "timestamp": time.time(),
        }) + "\n"
        if self.ipc_sock:
            try:
                self.ipc_sock.sendall(ready_msg.encode("utf-8"))
            except Exception:
                pass
        if self.write_stdout:
            sys.stdout.write(ready_msg)
            sys.stdout.flush()

        logger.info("Capture worker running on '%s' (PID %d)...", self.interface, os.getpid())

        while self.running:
            try:
                raw_bytes, _ = raw_sock.recvfrom(65535)
                ts = time.time()
                pkt = parse_packet_bytes(raw_bytes, ts)
                if pkt is not None:
                    self.packets_captured += 1
                    self.bytes_captured += pkt.packet_length
                    if pkt.protocol == 1:
                        self.icmp_packets += 1

                    self.send_packet(pkt)

                    if self.max_packets and self.packets_captured >= self.max_packets:
                        logger.info("Reached max_packets=%d, exiting.", self.max_packets)
                        break
            except socket.timeout:
                continue
            except Exception as exc:
                if self.running:
                    logger.error("Error reading packet from socket: %s", exc)
                break

        self.cleanup()

    def cleanup(self) -> None:
        """Close sockets and exit cleanly."""
        self.running = False
        if self.capture_sock:
            try:
                self.capture_sock.close()
            except Exception:
                pass
            self.capture_sock = None

        if self.ipc_sock:
            try:
                self.ipc_sock.close()
            except Exception:
                pass
            self.ipc_sock = None
        logger.info("Capture worker stopped. Captured %d packets (%d bytes).", self.packets_captured, self.bytes_captured)


def main() -> None:
    parser = argparse.ArgumentParser(description="XRL-IDARS Victim Namespace Packet Capture Worker")
    parser.add_argument("--iface", default="veth_xrl_vic", help="Interface to capture on (default: veth_xrl_vic)")
    parser.add_argument("--socket", default="/tmp/xrlids_capture.sock", help="Host IPC Unix domain socket path")
    parser.add_argument("--stdout", action="store_true", help="Also emit JSON stream to stdout")
    parser.add_argument("--max-packets", type=int, default=None, help="Stop after capturing N packets")
    args = parser.parse_args()

    worker = NetnsCaptureWorker(
        interface=args.iface,
        socket_path=args.socket,
        write_stdout=args.stdout,
        max_packets=args.max_packets,
    )
    worker.run()


if __name__ == "__main__":
    main()
