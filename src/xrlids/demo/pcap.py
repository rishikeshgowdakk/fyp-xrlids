"""Pure-Python PCAP reader, writer, and packet parser for reproducible demonstrations.

Standard library struct-based parser supporting LINKTYPE_ETHERNET (IPv4, TCP, UDP).
Zero external C-dependencies; verified on Python 3.14.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Generator, Iterable, Sequence

PCAP_GLOBAL_HEADER_FMT = "<IHHiIII"  # magic, v_maj, v_min, thiszone, sigfigs, snaplen, network
PCAP_PACKET_HEADER_FMT = "<IIII"     # ts_sec, ts_usec, incl_len, orig_len
PCAP_MAGIC_STANDARD = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NANO = 0xA1B23C4D
LINKTYPE_ETHERNET = 1


@dataclass(frozen=True)
class PacketInfo:
    """Structured information extracted from a raw network packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, etc.
    packet_length: int
    is_tcp: bool = False
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False


class PcapReader:
    """Streams parsed packets from a standard PCAP file."""

    def __init__(self, filepath: str | Path) -> None:
        self.filepath = Path(filepath)

    def read_packets(self) -> Generator[PacketInfo, None, None]:
        with open(self.filepath, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return

            magic, v_maj, v_min, tz, sig, snaplen, network = struct.unpack(PCAP_GLOBAL_HEADER_FMT, global_hdr)
            is_nano = magic == PCAP_MAGIC_NANO
            if magic not in (PCAP_MAGIC_STANDARD, PCAP_MAGIC_SWAPPED, PCAP_MAGIC_NANO):
                # Try big endian
                magic, v_maj, v_min, tz, sig, snaplen, network = struct.unpack(">IHHiIII", global_hdr)
                pkt_hdr_fmt = ">IIII"
            else:
                pkt_hdr_fmt = PCAP_PACKET_HEADER_FMT

            divisor = 1e9 if is_nano else 1e6

            while True:
                hdr_bytes = f.read(16)
                if len(hdr_bytes) < 16:
                    break
                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, hdr_bytes)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                ts = ts_sec + (ts_frac / divisor)
                parsed = parse_packet_bytes(pkt_data, ts)
                if parsed is not None:
                    yield parsed


def parse_packet_bytes(raw_bytes: bytes, timestamp: float) -> PacketInfo | None:
    """Parse Ethernet + IPv4 + TCP/UDP headers into PacketInfo."""
    # Minimum Ethernet frame is 14 bytes
    if len(raw_bytes) < 14:
        return None

    eth_type = struct.unpack("!H", raw_bytes[12:14])[0]
    if eth_type != 0x0800:
        # Not IPv4
        return None

    # IPv4 Header
    ip_bytes = raw_bytes[14:]
    if len(ip_bytes) < 20:
        return None

    version_ihl = ip_bytes[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(ip_bytes) < ihl:
        return None

    protocol = ip_bytes[9]
    src_ip = socket.inet_ntoa(ip_bytes[12:16])
    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
    total_len = struct.unpack("!H", ip_bytes[2:4])[0]
    packet_length = max(total_len, len(ip_bytes))

    transport_bytes = ip_bytes[ihl:]
    src_port = 0
    dst_port = 0
    syn = ack = rst = fin = False
    is_tcp = False

    if protocol == 6:  # TCP
        is_tcp = True
        if len(transport_bytes) >= 14:
            src_port, dst_port = struct.unpack("!HH", transport_bytes[0:4])
            flags = transport_bytes[13]
            fin = bool(flags & 0x01)
            syn = bool(flags & 0x02)
            rst = bool(flags & 0x04)
            ack = bool(flags & 0x10)
    elif protocol == 17:  # UDP
        if len(transport_bytes) >= 4:
            src_port, dst_port = struct.unpack("!HH", transport_bytes[0:4])

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=packet_length,
        is_tcp=is_tcp,
        syn=syn,
        ack=ack,
        rst=rst,
        fin=fin,
    )


def write_pcap(filepath: str | Path, packets: Iterable[tuple[float, bytes]]) -> None:
    """Write raw packets to a standard PCAP file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        # Write 24-byte global header
        f.write(struct.pack(PCAP_GLOBAL_HEADER_FMT, PCAP_MAGIC_STANDARD, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, data in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1e6)
            incl_len = len(data)
            orig_len = incl_len
            f.write(struct.pack(PCAP_PACKET_HEADER_FMT, ts_sec, ts_usec, incl_len, orig_len))
            f.write(data)


def build_raw_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int = 6,
    flags: dict[str, bool] | None = None,
    payload_len: int = 64,
) -> bytes:
    """Construct an Ethernet + IPv4 + TCP/UDP binary packet."""
    flags = flags or {}
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    payload = b"\x00" * payload_len

    if protocol == 6:  # TCP
        flag_byte = 0
        if flags.get("fin"):
            flag_byte |= 0x01
        if flags.get("syn"):
            flag_byte |= 0x02
        if flags.get("rst"):
            flag_byte |= 0x04
        if flags.get("ack"):
            flag_byte |= 0x10

        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            1000,       # seq
            2000,       # ack seq
            (5 << 4),   # data offset 20 bytes
            flag_byte,
            8192,       # window
            0,          # checksum
            0,          # urgent
        )
        transport_data = tcp_hdr + payload
    else:  # UDP
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        transport_data = udp_hdr + payload

    ip_total_len = 20 + len(transport_data)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,  # v4, ihl 5
        0,             # tos
        ip_total_len,
        12345,         # id
        0x4000,        # flags df
        64,            # ttl
        protocol,
        0,             # checksum
        src_bytes,
        dst_bytes,
    )

    return eth_hdr + ip_hdr + transport_data
