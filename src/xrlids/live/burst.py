"""Deterministic 1000-Packet Burst Generator for Phase 3E (EXP-P3-BURST-1000-001).

Implements the pre-registered specification:
"1000 packets from one click"
- Exactly 1000 packets
- Deterministic random seed (seed = 42)
- Composition: 800 benign packets (HTTP/DNS traffic mix) interleaved with
  a 200-packet SYN flood / port scan burst
- Strictly non-enforcing / observational / dry-run compatible
- Verifiable packet accounting, flow structure, and size distributions
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from xrlids.demo.pcap import PacketInfo


@dataclass(frozen=True)
class BurstConfig:
    """Deterministic configuration for the 1000-packet burst experiment."""

    total_packets: int = 1000
    benign_packets_count: int = 800
    attack_packets_count: int = 200
    seed: int = 42
    start_timestamp: float = 1700000000.0
    min_inter_packet_s: float = 0.0005
    max_inter_packet_s: float = 0.0030

    def __post_init__(self) -> None:
        if self.benign_packets_count + self.attack_packets_count != self.total_packets:
            raise ValueError(
                f"Packet count mismatch: {self.benign_packets_count} benign + "
                f"{self.attack_packets_count} attack != {self.total_packets} total"
            )


@dataclass
class BurstAudit:
    """Comprehensive accounting of the generated burst traffic."""

    total_packets: int
    benign_packets: int
    attack_packets: int
    benign_flows_expected: int
    attack_flows_expected: int
    min_packet_length: int
    max_packet_length: int
    mean_packet_length: float
    total_duration_s: float
    is_valid_1000_burst: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "benign_packets": self.benign_packets,
            "attack_packets": self.attack_packets,
            "benign_flows_expected": self.benign_flows_expected,
            "attack_flows_expected": self.attack_flows_expected,
            "min_packet_length": self.min_packet_length,
            "max_packet_length": self.max_packet_length,
            "mean_packet_length": round(self.mean_packet_length, 2),
            "total_duration_s": round(self.total_duration_s, 4),
            "is_valid_1000_burst": self.is_valid_1000_burst,
        }


def generate_1000_packet_burst(config: BurstConfig | None = None) -> list[PacketInfo]:
    """Generate a reproducible, deterministic sequence of exactly 1000 network packets.

    Traffic Structure:
    - 800 Benign Packets: 40 distinct completed TCP flows (20 packets each) representing
      multi-tier enterprise web and DNS interactions across internal clients and servers.
    - 200 Attack Packets: 10 distinct aggressive SYN flood / scan flows (20 packets each)
      originating from attacker IP 192.168.1.99 directed at ports 80 and 443.
    """
    cfg = config or BurstConfig()
    rng = random.Random(cfg.seed)

    benign_clients = [f"192.168.1.{i}" for i in range(10, 26)]
    web_servers = ["10.0.0.1", "10.0.0.2"]
    dns_server = "192.168.10.50"  # Critical infrastructure host
    attacker_ip = "192.168.1.99"

    # 1. Generate 40 Benign Flows (20 packets per flow = 800 packets)
    benign_flow_packets: list[list[PacketInfo]] = []
    current_time = cfg.start_timestamp

    for f_idx in range(40):
        client_ip = rng.choice(benign_clients)
        client_port = 40000 + f_idx
        is_dns = (f_idx % 8 == 0)
        server_ip = dns_server if is_dns else rng.choice(web_servers)
        server_port = 53 if is_dns else (80 if f_idx % 2 == 0 else 443)

        flow_pkts: list[PacketInfo] = []

        # Handshake
        flow_pkts.append(
            PacketInfo(0.0, client_ip, server_ip, client_port, server_port, 6, 64, is_tcp=True, syn=True)
        )
        flow_pkts.append(
            PacketInfo(0.0, server_ip, client_ip, server_port, client_port, 6, 64, is_tcp=True, syn=True, ack=True)
        )
        flow_pkts.append(
            PacketInfo(0.0, client_ip, server_ip, client_port, server_port, 6, 54, is_tcp=True, ack=True)
        )

        # Data exchange (14 packets)
        for d_idx in range(14):
            is_client = (d_idx % 2 == 0)
            src_ip = client_ip if is_client else server_ip
            dst_ip = server_ip if is_client else client_ip
            src_p = client_port if is_client else server_port
            dst_p = server_port if is_client else client_port
            pkt_len = rng.choice([128, 256, 512, 1024, 1460]) if not is_client else rng.choice([64, 128, 256])
            flow_pkts.append(
                PacketInfo(0.0, src_ip, dst_ip, src_p, dst_p, 6, pkt_len, is_tcp=True, ack=True)
            )

        # Teardown (3 packets: FIN from server, ACK from client, FIN/ACK from client)
        flow_pkts.append(
            PacketInfo(0.0, server_ip, client_ip, server_port, client_port, 6, 54, is_tcp=True, fin=True, ack=True)
        )
        flow_pkts.append(
            PacketInfo(0.0, client_ip, server_ip, client_port, server_port, 6, 54, is_tcp=True, ack=True)
        )
        flow_pkts.append(
            PacketInfo(0.0, client_ip, server_ip, client_port, server_port, 6, 54, is_tcp=True, fin=True, ack=True)
        )

        assert len(flow_pkts) == 20
        benign_flow_packets.append(flow_pkts)

    # 2. Generate 10 Attack Flows (20 packets per flow = 200 packets)
    attack_flow_packets: list[list[PacketInfo]] = []
    for a_idx in range(10):
        target_ip = web_servers[a_idx % 2]
        target_port = 80 if a_idx % 2 == 0 else 443
        attack_pkts: list[PacketInfo] = []

        # 19 rapid SYN packets with varied source ports
        for s_idx in range(19):
            src_port = 55000 + (a_idx * 20) + s_idx
            attack_pkts.append(
                PacketInfo(0.0, attacker_ip, target_ip, src_port, target_port, 6, 64, is_tcp=True, syn=True)
            )

        # 1 trailing RST to trigger D-006 completion
        last_port = 55000 + (a_idx * 20) + 18
        attack_pkts.append(
            PacketInfo(0.0, target_ip, attacker_ip, target_port, last_port, 6, 54, is_tcp=True, rst=True, ack=True)
        )

        assert len(attack_pkts) == 20
        attack_flow_packets.append(attack_pkts)

    # 3. Interleave flows to simulate concurrent live network multiplexing
    all_packets: list[PacketInfo] = []
    # Interleave benign and attack packets
    b_ptrs = [0] * len(benign_flow_packets)
    a_ptrs = [0] * len(attack_flow_packets)

    total_target = cfg.total_packets
    while len(all_packets) < total_target:
        # Determine whether to emit benign or attack packet
        choose_attack = (rng.random() < (cfg.attack_packets_count / cfg.total_packets)) and any(
            p < 20 for p in a_ptrs
        )

        if choose_attack:
            # Pick an attack flow with remaining packets
            available = [i for i, p in enumerate(a_ptrs) if p < 20]
            if available:
                flow_idx = rng.choice(available)
                pkt = attack_flow_packets[flow_idx][a_ptrs[flow_idx]]
                a_ptrs[flow_idx] += 1
            else:
                # Fallback to benign
                available_b = [i for i, p in enumerate(b_ptrs) if p < 20]
                flow_idx = rng.choice(available_b)
                pkt = benign_flow_packets[flow_idx][b_ptrs[flow_idx]]
                b_ptrs[flow_idx] += 1
        else:
            available_b = [i for i, p in enumerate(b_ptrs) if p < 20]
            if available_b:
                flow_idx = rng.choice(available_b)
                pkt = benign_flow_packets[flow_idx][b_ptrs[flow_idx]]
                b_ptrs[flow_idx] += 1
            else:
                available = [i for i, p in enumerate(a_ptrs) if p < 20]
                flow_idx = rng.choice(available)
                pkt = attack_flow_packets[flow_idx][a_ptrs[flow_idx]]
                a_ptrs[flow_idx] += 1

        delta_t = rng.uniform(cfg.min_inter_packet_s, cfg.max_inter_packet_s)
        current_time += delta_t

        # Create packet with monotonic timestamp
        timed_pkt = PacketInfo(
            timestamp=round(current_time, 6),
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol,
            packet_length=pkt.packet_length,
            is_tcp=pkt.is_tcp,
            syn=pkt.syn,
            ack=pkt.ack,
            rst=pkt.rst,
            fin=pkt.fin,
        )
        all_packets.append(timed_pkt)

    assert len(all_packets) == 1000, f"Expected exactly 1000 packets, got {len(all_packets)}"
    return all_packets


def audit_burst(packets: Sequence[PacketInfo], attacker_ip: str = "192.168.1.99") -> BurstAudit:
    """Inspect and return verified accounting metrics for a packet sequence."""
    total = len(packets)
    attack = sum(1 for p in packets if p.src_ip == attacker_ip or p.dst_ip == attacker_ip)
    benign = sum(1 for p in packets if p.src_ip != attacker_ip and p.dst_ip != attacker_ip)
    lengths = [p.packet_length for p in packets]

    dur = 0.0
    if total > 1:
        dur = max(0.0, packets[-1].timestamp - packets[0].timestamp)

    is_valid = (total == 1000 and benign == 800 and attack == 200)

    return BurstAudit(
        total_packets=total,
        benign_packets=benign,
        attack_packets=attack,
        benign_flows_expected=40,
        attack_flows_expected=10,
        min_packet_length=min(lengths) if lengths else 0,
        max_packet_length=max(lengths) if lengths else 0,
        mean_packet_length=float(np.mean(lengths)) if lengths else 0.0,
        total_duration_s=dur,
        is_valid_1000_burst=is_valid,
    )
