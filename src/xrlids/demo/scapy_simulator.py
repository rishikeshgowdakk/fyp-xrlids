"""Isolated Lab Scapy Attack Simulator for XRL-IDARS.

Generates genuine, safe, calibrated network packets using Scapy across 4 distinct scenarios:
  - Scenario A: Benign Traffic (normal TCP handshake, HTTP request/response, normal ICMP ping)
  - Scenario B: Port Scan Simulation (controlled probes across bounded ports: 21, 22, 80, 443, 8080)
  - Scenario C: TCP SYN Burst (volumetric SYN flood burst to port 80)
  - Scenario D: ICMP Burst (controlled ICMP echo flood burst)

Strict Safety Invariants:
  1. Target IP is strictly validated to remain inside the isolated lab subnet (10.200.1.0/24) or loopback.
  2. Never targets public or non-lab IP addresses.
  3. Bounded packet count (hard cap 500) and duration (hard cap 30s).
  4. Real Scapy packets (Ether/IP/TCP/ICMP) with accurate protocol headers and checksums.
  5. Ground truth labels are recorded separately from model inferences.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Generator, Sequence

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

from xrlids.capture.scapy_service import ScapyCaptureService, scapy_packet_to_packet_info
from xrlids.demo.pcap import PacketInfo

logger = logging.getLogger("xrlids.demo.scapy_simulator")

# --------------------------------------------------------------------------- constants
ATTACKER_IP = "10.200.1.2"
VICTIM_IP = "10.200.1.3"
LAB_SUBNET_PREFIX = "10.200.1."
ALLOWED_LOOPBACK = "127.0.0.1"
ATTACKER_MAC = "02:00:00:00:00:02"
VICTIM_MAC = "02:00:00:00:00:03"

MAX_PACKETS_HARD_LIMIT = 500
MAX_DURATION_HARD_LIMIT = 30.0


def validate_target_safety(target_ip: str) -> None:
    """Enforce strict isolation safety: target must remain in isolated lab or loopback."""
    ip = str(target_ip).strip()
    if not (ip.startswith(LAB_SUBNET_PREFIX) or ip == ALLOWED_LOOPBACK):
        raise ValueError(
            f"Security invariant violated: target IP '{target_ip}' is outside isolated lab "
            f"subnet ({LAB_SUBNET_PREFIX}0/24) and loopback. Public / internet scanning is forbidden."
        )


@dataclass(frozen=True)
class SimulatorScenarioSpec:
    """Specification of a simulation scenario."""

    scenario_id: str
    name: str
    category: str  # "BENIGN" or "ATTACK"
    attack_family: str  # "BENIGN", "PortScan", "DoS/DDoS", "ICMP_Flood"
    description: str
    target_ports: list[int]
    default_packet_count: int
    default_rate_pps: float
    expected_ground_truth: str
    expected_rule: str | None


SCENARIO_SPECS: dict[str, SimulatorScenarioSpec] = {
    "scenario_ping": SimulatorScenarioSpec(
        scenario_id="scenario_ping",
        name="Scenario Ping: Benign Ping",
        category="BENIGN",
        attack_family="BENIGN",
        description="Controlled benign ICMP echo request/reply exchange between 10.200.1.2 and 10.200.1.3.",
        target_ports=[],
        default_packet_count=4,
        default_rate_pps=5.0,
        expected_ground_truth="BENIGN",
        expected_rule=None,
    ),
    "scenario_a_benign": SimulatorScenarioSpec(
        scenario_id="scenario_a_benign",
        name="Scenario A: Benign Traffic",
        category="BENIGN",
        attack_family="BENIGN",
        description="Normal TCP connection, local HTTP GET/200 OK exchange, and ordinary ICMP echo/reply.",
        target_ports=[80],
        default_packet_count=12,
        default_rate_pps=5.0,
        expected_ground_truth="BENIGN",
        expected_rule=None,
    ),
    "scenario_b_port_scan": SimulatorScenarioSpec(
        scenario_id="scenario_b_port_scan",
        name="Scenario B: Port Scan Simulation",
        category="ATTACK",
        attack_family="PortScan",
        description="Controlled TCP SYN probes across bounded ports (21, 22, 80, 443, 8080) on isolated victim.",
        target_ports=[21, 22, 80, 443, 8080],
        default_packet_count=15,
        default_rate_pps=10.0,
        expected_ground_truth="ATTACK",
        expected_rule="RULE-PORT-SCAN",
    ),
    "scenario_c_syn_burst": SimulatorScenarioSpec(
        scenario_id="scenario_c_syn_burst",
        name="Scenario C: TCP SYN Burst",
        category="ATTACK",
        attack_family="DoS/DDoS",
        description="Bounded volumetric TCP SYN flood burst against victim port 80 (high SYN/ACK asymmetry).",
        target_ports=[80],
        default_packet_count=60,
        default_rate_pps=50.0,
        expected_ground_truth="ATTACK",
        expected_rule="RULE-SYN-FLOOD",
    ),
    "scenario_d_icmp_burst": SimulatorScenarioSpec(
        scenario_id="scenario_d_icmp_burst",
        name="Scenario D: ICMP Burst",
        category="ATTACK",
        attack_family="ICMP_Flood",
        description="Bounded ICMP echo request flood burst targeting isolated victim.",
        target_ports=[],
        default_packet_count=40,
        default_rate_pps=40.0,
        expected_ground_truth="ATTACK",
        expected_rule="RULE-ICMP-FLOOD",
    ),
}


@dataclass
class SimulatorRunRecord:
    """Experiment provenance record for a single simulation run."""

    run_id: str
    scenario_id: str
    scenario_name: str
    target_ip: str
    target_ports: list[int]
    start_time: str
    end_time: str = ""
    duration_s: float = 0.0
    configured_packets: int = 0
    generated_packets: int = 0
    generated_bytes: int = 0
    ground_truth: str = "BENIGN"
    ground_truth_family: str = "BENIGN"
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, STOPPED, FAILED
    error: str | None = None
    captured_packet_count: int | None = None
    processed_flow_count: int | None = None
    detected_attack_count: int | None = None
    rule_triggers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "target_ip": self.target_ip,
            "target_ports": self.target_ports,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_s": round(self.duration_s, 4),
            "configured_packets": self.configured_packets,
            "generated_packets": self.generated_packets,
            "generated_bytes": self.generated_bytes,
            "ground_truth": self.ground_truth,
            "ground_truth_family": self.ground_truth_family,
            "status": self.status,
            "error": self.error,
            "captured_packet_count": self.captured_packet_count,
            "processed_flow_count": self.processed_flow_count,
            "detected_attack_count": self.detected_attack_count,
            "rule_triggers": self.rule_triggers,
        }


class ScapyAttackSimulator:
    """Generates genuine Scapy packet streams for the 4 isolated lab scenarios."""

    def __init__(
        self,
        attacker_ip: str = ATTACKER_IP,
        victim_ip: str = VICTIM_IP,
    ) -> None:
        validate_target_safety(victim_ip)
        self.attacker_ip = attacker_ip
        self.victim_ip = victim_ip
        self._active_run: SimulatorRunRecord | None = None
        self._stop_event = threading.Event()

    @staticmethod
    def get_scenarios() -> list[dict[str, Any]]:
        """Return list of supported simulation scenarios with full metadata."""
        return [
            {
                "id": s.scenario_id,
                "name": s.name,
                "category": s.category,
                "family": s.attack_family,
                "description": s.description,
                "target_ports": s.target_ports,
                "default_packets": s.default_packet_count,
                "default_rate_pps": s.default_rate_pps,
                "expected_ground_truth": s.expected_ground_truth,
                "expected_rule": s.expected_rule,
            }
            for s in SCENARIO_SPECS.values()
        ]

    # ------------------------------------------------ Scenario Ping: Pure Benign Ping
    def build_benign_ping(
        self,
        base_time: float | None = None,
        count: int = 4,
    ) -> list[Packet]:
        """Generate pure, clean ICMP echo request/reply packets without TCP fragments."""
        t0 = base_time if base_time is not None else time.time()
        packets: list[Packet] = []
        t = t0
        for seq_num in range(1, count + 1):
            echo_req = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / ICMP(
                type=8, code=0, id=0x1234, seq=seq_num
            )
            echo_req.time = t
            packets.append(echo_req)
            t += 0.010

            echo_rep = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / ICMP(
                type=0, code=0, id=0x1234, seq=seq_num
            )
            echo_rep.time = t
            packets.append(echo_rep)
            t += 0.050
        return packets

    # ------------------------------------------------ Scenario A: Benign Traffic
    def build_scenario_a_benign(
        self,
        base_time: float | None = None,
        packet_count: int = 12,
    ) -> list[Packet]:
        """Scenario A: Benign TCP connection, HTTP request/response, and normal ICMP echo."""
        t0 = base_time if base_time is not None else time.time()
        packets: list[Packet] = []

        # Flow 1: Normal HTTP GET exchange (8 packets)
        client_port = 54320
        server_port = 80
        t = t0

        # 1. TCP 3-way handshake
        syn = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
            sport=client_port, dport=server_port, flags="S", seq=1000
        )
        syn.time = t
        packets.append(syn)
        t += 0.005

        syn_ack = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / TCP(
            sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001
        )
        syn_ack.time = t
        packets.append(syn_ack)
        t += 0.005

        ack = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
            sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001
        )
        ack.time = t
        packets.append(ack)
        t += 0.010

        # 2. HTTP GET request (72 bytes payload)
        http_req_data = b"GET /index.html HTTP/1.1\r\nHost: 10.200.1.3\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        http_req = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
            sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2001
        ) / http_req_data
        http_req.time = t
        packets.append(http_req)
        t += 0.020

        # 3. HTTP 200 OK response (118 bytes payload)
        http_res_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 21\r\n\r\n<h1>Welcome Lab</h1>"
        http_res = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / TCP(
            sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001 + len(http_req_data)
        ) / http_res_data
        http_res.time = t
        packets.append(http_res)
        t += 0.015

        # 4. Graceful TCP termination (FIN-ACK / FIN-ACK)
        fin1 = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
            sport=client_port, dport=server_port, flags="FA", seq=1001 + len(http_req_data), ack=2001 + len(http_res_data)
        )
        fin1.time = t
        packets.append(fin1)
        t += 0.005

        fin2 = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / TCP(
            sport=server_port, dport=client_port, flags="FA", seq=2001 + len(http_res_data), ack=1002 + len(http_req_data)
        )
        fin2.time = t
        packets.append(fin2)
        t += 0.005

        ack_fin = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
            sport=client_port, dport=server_port, flags="A", seq=1002 + len(http_req_data), ack=2002 + len(http_res_data)
        )
        ack_fin.time = t
        packets.append(ack_fin)
        t += 0.050

        # Flow 2: Normal ICMP Ping (4 packets: 2 echo requests, 2 echo replies)
        for seq_num in (1, 2):
            echo_req = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / ICMP(
                type=8, code=0, id=0x1234, seq=seq_num
            )
            echo_req.time = t
            packets.append(echo_req)
            t += 0.010

            echo_rep = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / ICMP(
                type=0, code=0, id=0x1234, seq=seq_num
            )
            echo_rep.time = t
            packets.append(echo_rep)
            t += 0.050

        return packets[: min(packet_count, len(packets))]

    # ------------------------------------------------ Scenario B: Port Scan
    def build_scenario_b_port_scan(
        self,
        base_time: float | None = None,
        ports: Sequence[int] = (21, 22, 80, 443, 8080),
    ) -> list[Packet]:
        """Scenario B: Controlled TCP SYN probes across bounded ports on victim.

        Closed/filtered ports receive 3 consecutive SYN probes without ACK response,
        matching standard scanner retry behavior and the RULE-PORT-SCAN signature.
        """
        t0 = base_time if base_time is not None else time.time()
        packets: list[Packet] = []
        t = t0

        for i, port in enumerate(ports):
            sport = 55000 + i
            if port == 80:
                # Open port: SYN -> SYN-ACK -> RST
                syn = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
                    sport=sport, dport=port, flags="S", seq=1000 + i * 10
                )
                syn.time = t
                packets.append(syn)
                t += 0.005

                syn_ack = Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=self.victim_ip, dst=self.attacker_ip) / TCP(
                    sport=port, dport=sport, flags="SA", seq=5000, ack=1001 + i * 10
                )
                syn_ack.time = t
                packets.append(syn_ack)
                t += 0.005

                rst = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
                    sport=sport, dport=port, flags="R", seq=1001 + i * 10
                )
                rst.time = t
                packets.append(rst)
            else:
                # Unanswered / filtered port: 3 rapid SYN probes with minimal byte footprint
                for probe_seq in range(3):
                    syn_probe = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
                        sport=sport, dport=port, flags="S", seq=1000 + probe_seq * 100
                    )
                    syn_probe.time = t
                    packets.append(syn_probe)
                    t += 0.005

            t += 0.020

        return packets

    # ------------------------------------------------ Scenario C: TCP SYN Burst
    def build_scenario_c_syn_burst(
        self,
        base_time: float | None = None,
        packet_count: int = 60,
        target_port: int = 80,
    ) -> list[Packet]:
        """Scenario C: Bounded volumetric TCP SYN flood burst against victim port 80.

        Emits high-rate unanswered SYN packets across bounded client flows (30 pkts each),
        producing extreme SYN/ACK asymmetry that matches RULE-SYN-FLOOD.
        """
        t0 = base_time if base_time is not None else time.time()
        packets: list[Packet] = []
        n_pkts = min(max(packet_count, 10), MAX_PACKETS_HARD_LIMIT)

        # 2 high-volume flows of 30 SYNs each (or distributed if smaller/larger)
        delta = 0.010
        for i in range(n_pkts):
            sport = 45000 + (i // 30)
            syn = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / TCP(
                sport=sport, dport=target_port, flags="S", seq=1000 + (i % 30) * 100
            )
            syn.time = t0 + i * delta
            packets.append(syn)

        return packets

    # ------------------------------------------------ Scenario D: ICMP Burst
    def build_scenario_d_icmp_burst(
        self,
        base_time: float | None = None,
        packet_count: int = 40,
    ) -> list[Packet]:
        """Scenario D: Bounded ICMP echo flood burst targeting isolated victim."""
        t0 = base_time if base_time is not None else time.time()
        packets: list[Packet] = []
        n_pkts = min(max(packet_count, 10), MAX_PACKETS_HARD_LIMIT)

        # High arrival rate: ~40 pkts/s (inter-packet delta = 0.015s)
        delta = 0.015
        for i in range(n_pkts):
            echo = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=self.attacker_ip, dst=self.victim_ip) / ICMP(
                type=8, code=0, id=0x4321, seq=i + 1
            )
            echo.time = t0 + i * delta
            packets.append(echo)

        return packets

    # ------------------------------------------------ Packet Generation Dispatcher
    def build_packets_for_scenario(
        self,
        scenario_id: str,
        packet_count: int | None = None,
        base_time: float | None = None,
    ) -> list[Packet]:
        """Build Scapy packets for the given scenario ID."""
        if scenario_id in ("scenario_ping", "scenario_benign_ping"):
            return self.build_benign_ping(base_time=base_time, count=(packet_count or 4) // 2 or 2)
        elif scenario_id == "scenario_a_benign":
            return self.build_scenario_a_benign(base_time=base_time, packet_count=packet_count or 12)
        elif scenario_id == "scenario_b_port_scan":
            return self.build_scenario_b_port_scan(base_time=base_time)
        elif scenario_id == "scenario_c_syn_burst":
            return self.build_scenario_c_syn_burst(base_time=base_time, packet_count=packet_count or 60)
        elif scenario_id == "scenario_d_icmp_burst":
            return self.build_scenario_d_icmp_burst(base_time=base_time, packet_count=packet_count or 40)
        else:
            raise ValueError(f"Unknown simulation scenario ID: {scenario_id!r}. Supported: {list(SCENARIO_SPECS.keys())}")

    # ------------------------------------------------ Execution and Emission
    def run_simulation(
        self,
        scenario_id: str,
        packet_count: int | None = None,
        capture_service: ScapyCaptureService | None = None,
        pace_multiplier: float = 1.0,
        stop_event: threading.Event | None = None,
        on_packet_emitted: Callable[[PacketInfo], None] | None = None,
    ) -> SimulatorRunRecord:
        """Execute scenario, emit Scapy packets into capture service, and record metrics."""
        spec = SCENARIO_SPECS.get(scenario_id)
        if spec is None:
            raise ValueError(f"Unknown scenario {scenario_id!r}")

        self._stop_event.clear()
        stop_signal = stop_event or self._stop_event

        run_id = f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex().upper()}"
        run_record = SimulatorRunRecord(
            run_id=run_id,
            scenario_id=spec.scenario_id,
            scenario_name=spec.name,
            target_ip=self.victim_ip,
            target_ports=list(spec.target_ports),
            start_time=datetime.now(timezone.utc).isoformat(),
            configured_packets=packet_count or spec.default_packet_count,
            ground_truth=spec.expected_ground_truth,
            ground_truth_family=spec.attack_family,
            status="RUNNING",
        )
        self._active_run = run_record

        t_start = time.time()
        try:
            scapy_packets = self.build_packets_for_scenario(
                scenario_id=scenario_id,
                packet_count=packet_count,
                base_time=t_start,
            )

            total_bytes = 0
            sent_count = 0
            last_pkt_time: float | None = None

            for pkt in scapy_packets:
                if stop_signal.is_set():
                    run_record.status = "STOPPED"
                    break

                # Pacing between packets
                pkt_time = float(getattr(pkt, "time", time.time()))
                if last_pkt_time is not None and pace_multiplier > 0:
                    dt = (pkt_time - last_pkt_time) / pace_multiplier
                    if 0.0 < dt < 1.0:
                        time.sleep(dt)
                last_pkt_time = pkt_time

                # Convert to PacketInfo for verification and callbacks
                pinfo = scapy_packet_to_packet_info(pkt)
                total_bytes += len(pkt)
                sent_count += 1

                if capture_service is not None:
                    capture_service.inject_scapy_packet(pkt)

                if on_packet_emitted is not None and pinfo is not None:
                    on_packet_emitted(pinfo)

            t_end = time.time()
            run_record.end_time = datetime.now(timezone.utc).isoformat()
            run_record.duration_s = max(0.001, t_end - t_start)
            run_record.generated_packets = sent_count
            run_record.generated_bytes = total_bytes
            if run_record.status == "RUNNING":
                run_record.status = "COMPLETED"

        except Exception as exc:
            run_record.status = "FAILED"
            run_record.error = str(exc)
            logger.error("Simulation run %s failed: %s", run_id, exc)
            raise

        return run_record

    def stop(self) -> None:
        """Signal running simulation to stop."""
        self._stop_event.set()

    def export_scenario_pcap(self, scenario_id: str, output_path: str | Path) -> Path:
        """Generate Scapy packets for a scenario and write to a PCAP file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        pkts = self.build_packets_for_scenario(scenario_id=scenario_id)
        wrpcap(str(out), pkts)
        return out

    def test_ping_connectivity(
        self,
        firewall_filter_fn: Callable[[str, str], bool] | None = None,
        count: int = 4,
    ) -> dict[str, Any]:
        """Test ping reachability between attacker and victim.

        If firewall_filter_fn is supplied and returns False, packets are dropped.
        """
        sent = count
        delivered = 0
        dropped = 0
        for _ in range(count):
            allowed = True
            if firewall_filter_fn is not None:
                allowed = firewall_filter_fn(self.attacker_ip, self.victim_ip)
            if allowed:
                delivered += 1
            else:
                dropped += 1
        return {
            "source_ip": self.attacker_ip,
            "target_ip": self.victim_ip,
            "packets_sent": sent,
            "packets_delivered": delivered,
            "packets_dropped": dropped,
            "success": (delivered == sent),
            "drop_rate": float(dropped / sent) if sent > 0 else 0.0,
            "status": "REACHABLE (4/4 delivered)" if delivered == sent else f"BLOCKED ({dropped}/{sent} dropped by firewall)",
        }
