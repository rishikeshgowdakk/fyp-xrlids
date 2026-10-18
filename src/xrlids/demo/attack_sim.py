"""Attack simulator: calibrated synthetic attack scenarios for the Live Monitor.

Every scenario is a deterministic packet script (TCP only) that is synthesised in
memory and pushed through the *exact* observational live pipeline
(FlowBuilder with the D-006 completion policy -> frozen R10 feature extraction ->
frozen CIC-IDS2017 Random Forest detector, EXP-P1-CIC2017-R10-001). Nothing is
transmitted on any network interface and no firewall/routing state is touched.

Calibration (see the "expected_score" fields, verified by
``scripts/demo/verify_attack_scenarios.py``):

- Scenario parameters were chosen by probing the physically realisable packet-script
  space (2..400 packets, 54..1500-byte lengths, 0.1 ms..8 s durations, flag mixes)
  and scoring each script end-to-end through the frozen pipeline.
- The frozen detector's *physically reproducible* high-confidence region is the
  low-and-slow flow family: 2..4 packets, 3..8 s duration, small equal-size payloads
  (scores 0.55..0.99 -> HIGH/ALERT bands). These are the "detected" scenarios.
- Classic fast patterns (SYN floods, HTTP floods, port sweeps) score ~0.0..0.2 with
  this frozen model: its learned flood/scan regions rely on CIC FlowMeter artefacts
  (e.g. packet-length standard deviations above the physical 1500-byte limit, flows
  of thousands of packets) that a clean synthetic capture cannot reproduce. Those
  scenarios ship as explicit *evasion demos* with expected band NONE, so the console
  shows the model's real behaviour rather than a staged detection.

Pacing requirement: the calibrated scores are time-shape dependent (flow_duration_ms,
flow_packets_per_s, flow_bytes_per_s). Injections therefore run at 1x speed (real
durations); do not rescale. Wall-clock restamping at emission preserves inter-packet
deltas, so live scores match the calibrated values within one digit of tolerance.

All attacker addresses use the RFC 5737 documentation range (203.0.113.0/24); the
victim matches the bundled sample capture (192.168.1.10).
"""

from __future__ import annotations

from dataclasses import dataclass

from xrlids.demo.pcap import PacketInfo

# --------------------------------------------------------------------------- constants
VICTIM_IP = "192.168.1.10"
BASE_TIMESTAMP = 1000.0  # Script time base; the dashboard restamps packets to wall clock.
CALIBRATION_MODEL = "EXP-P1-CIC2017-R10-001 (frozen CIC-IDS2017 R10 Random Forest)"


@dataclass(frozen=True)
class ScriptPacket:
    """One synthetic packet with a script-relative offset in seconds."""

    offset_s: float
    length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False


@dataclass(frozen=True)
class ScenarioSpec:
    """A calibrated attack scenario (a small collection of packet scripts)."""

    id: str
    name: str
    description: str
    category: str  # "low_and_slow" | "flood" | "scan"
    attacker_ip: str
    src_port: int
    dst_port: int
    packets: tuple[ScriptPacket, ...]
    expected_flows: int
    expected_score: float
    expected_band: str  # "HIGH" (>=0.85) | "ALERT" (>=0.50) | "NONE"
    calibration_note: str

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def duration_s(self) -> float:
        return max(p.offset_s for p in self.packets) if self.packets else 0.0


# ------------------------------------------------------------------ script helpers
def _fwd(
    attacker_ip: str, src_port: int, dst_port: int, offset_s: float, length: int, **flags: bool
) -> ScriptPacket:
    """Attacker -> victim packet."""
    return ScriptPacket(
        offset_s=offset_s, length=length, src_ip=attacker_ip, dst_ip=VICTIM_IP,
        src_port=src_port, dst_port=dst_port, **flags,
    )


def _rev(
    attacker_ip: str, src_port: int, dst_port: int, offset_s: float, length: int, **flags: bool
) -> ScriptPacket:
    """Victim -> attacker packet (response direction)."""
    return ScriptPacket(
        offset_s=offset_s, length=length, src_ip=VICTIM_IP, dst_ip=attacker_ip,
        src_port=dst_port, dst_port=src_port, **flags,
    )


def _slow_trickle_2(
    attacker_ip: str, sport: int, dport: int, gap_s: float, length: int
) -> tuple[ScriptPacket, ...]:
    """Two-packet slow exchange: SYN, then ACK+RST after ``gap_s`` seconds."""
    return (
        _fwd(attacker_ip, sport, dport, 0.0, length, syn=True),
        _fwd(attacker_ip, sport, dport, gap_s, length, ack=True, rst=True),
    )


def _slow_trickle_3(
    attacker_ip: str, sport: int, dport: int, steps_s: tuple[float, float], length: int
) -> tuple[ScriptPacket, ...]:
    """Three-packet slow exchange: SYN, ACK, then RST at the given offsets."""
    t1, t2 = steps_s
    return (
        _fwd(attacker_ip, sport, dport, 0.0, length, syn=True),
        _fwd(attacker_ip, sport, dport, t1, length, ack=True),
        _fwd(attacker_ip, sport, dport, t2, length, rst=True),
    )


def _burst(
    attacker_ip: str,
    sport: int,
    dport: int,
    count: int,
    dur_s: float,
    length_for: "list[int] | tuple[int, ...]",
    ack: bool = False,
) -> tuple[ScriptPacket, ...]:
    """A paced burst of ``count`` packets over ``dur_s`` seconds, closed with a final RST."""
    step = dur_s / max(count, 1)
    packets = [
        _fwd(attacker_ip, sport, dport, i * step, length_for[i % len(length_for)], ack=ack)
        for i in range(count)
    ]
    packets.append(_fwd(attacker_ip, sport, dport, dur_s + 0.001, 54, rst=True))
    return tuple(packets)


def _port_sweep(
    attacker_ip: str, base_sport: int, probes: int, step_s: float
) -> tuple[ScriptPacket, ...]:
    """Sequential SYN probes with one RST response each (two-packet flows)."""
    packets: list[ScriptPacket] = []
    for i in range(probes):
        t = i * step_s
        sport, dport = base_sport + i, 20 + i
        packets.append(_fwd(attacker_ip, sport, dport, t, 54, syn=True))
        packets.append(_rev(attacker_ip, sport, dport, t + 0.001, 54, rst=True))
    return tuple(packets)


# --------------------------------------------------------------------- scenarios
SCENARIOS: dict[str, ScenarioSpec] = {
    "slow_http_dos": ScenarioSpec(
        id="slow_http_dos",
        name="Slow HTTP DoS (slowhttptest-style)",
        description=(
            "Two-packet HTTP exchange held open for ~3.25 s (slowhttptest-style slow request). "
            "The frozen detector separates this slow-rate shape from benign traffic with high confidence."
        ),
        category="low_and_slow",
        attacker_ip="203.0.113.66",
        src_port=41001,
        dst_port=80,
        packets=_slow_trickle_2("203.0.113.66", 41001, 80, 3.25, 356),
        expected_flows=1,
        expected_score=0.9910,
        expected_band="HIGH",
        calibration_note="verified through FlowBuilder -> frozen R10 -> frozen RF",
    ),
    "slow_http_dos_lite": ScenarioSpec(
        id="slow_http_dos_lite",
        name="Slow HTTP DoS (minimal headers)",
        description=(
            "Same slow-request shape with 200-byte payloads; the detector still flags it, "
            "slightly below the full-payload variant."
        ),
        category="low_and_slow",
        attacker_ip="203.0.113.67",
        src_port=41002,
        dst_port=80,
        packets=_slow_trickle_2("203.0.113.67", 41002, 80, 3.27, 200),
        expected_flows=1,
        expected_score=0.9163,
        expected_band="HIGH",
        calibration_note="verified through FlowBuilder -> frozen R10 -> frozen RF",
    ),
    "slowloris_session": ScenarioSpec(
        id="slowloris_session",
        name="Slowloris-style session",
        description=(
            "Three packets spread over 5 s (partial-request keep-alive pattern). "
            "Alert-level detection; below the HIGH band."
        ),
        category="low_and_slow",
        attacker_ip="203.0.113.68",
        src_port=41003,
        dst_port=80,
        packets=_slow_trickle_3("203.0.113.68", 41003, 80, (2.5, 5.0), 356),
        expected_flows=1,
        expected_score=0.7667,
        expected_band="ALERT",
        calibration_note="verified through FlowBuilder -> frozen R10 -> frozen RF",
    ),
    "low_rate_drip": ScenarioSpec(
        id="low_rate_drip",
        name="Low-rate drip (slow data trickle)",
        description=(
            "Three 556-byte packets spread over 8 s to port 443 (low-and-slow data drip). "
            "Alert-level detection at the research threshold."
        ),
        category="low_and_slow",
        attacker_ip="203.0.113.69",
        src_port=41004,
        dst_port=443,
        packets=_slow_trickle_3("203.0.113.69", 41004, 443, (4.0, 8.0), 556),
        expected_flows=1,
        expected_score=0.5476,
        expected_band="ALERT",
        calibration_note="verified through FlowBuilder -> frozen R10 -> frozen RF",
    ),
    "syn_flood": ScenarioSpec(
        id="syn_flood",
        name="SYN flood burst (evasion demo)",
        description=(
            "201-packet SYN burst over 1 s, closed with RST. A clean synthetic SYN flood that the "
            "frozen model does NOT flag: its learned flood region relies on CIC FlowMeter artefacts "
            "(see module docstring). Shown deliberately as a documented limitation."
        ),
        category="flood",
        attacker_ip="203.0.113.80",
        src_port=41005,
        dst_port=80,
        packets=_burst("203.0.113.80", 41005, 80, 200, 1.0, (60,)),
        expected_flows=1,
        expected_score=0.0002,
        expected_band="NONE",
        calibration_note="evasion demo: expected non-detection (clean synthetic flood)",
    ),
    "http_flood": ScenarioSpec(
        id="http_flood",
        name="HTTP flood burst (evasion demo)",
        description=(
            "301-packet HTTP flood (54/1460-byte mix) over 1.5 s. Expected non-detection for the same "
            "reason as the SYN flood evasion demo."
        ),
        category="flood",
        attacker_ip="203.0.113.81",
        src_port=41006,
        dst_port=80,
        packets=_burst("203.0.113.81", 41006, 80, 300, 1.5, (54, 1460, 54), ack=True),
        expected_flows=1,
        expected_score=0.0290,
        expected_band="NONE",
        calibration_note="evasion demo: expected non-detection (clean synthetic flood)",
    ),
    "port_sweep": ScenarioSpec(
        id="port_sweep",
        name="Port sweep scan (evasion demo)",
        description=(
            "40-port sequential sweep (SYN probe + RST response per port). Expected non-detection on "
            "this clean synthetic signature (same artefact-region limitation as the flood demos)."
        ),
        category="scan",
        attacker_ip="203.0.113.82",
        src_port=50000,
        dst_port=20,
        packets=_port_sweep("203.0.113.82", 50000, probes=40, step_s=0.05),
        expected_flows=40,
        expected_score=0.0169,
        expected_band="NONE",
        calibration_note="evasion demo: expected non-detection (clean synthetic scan)",
    ),
}


# ----------------------------------------------------------------------- public API
def build_scenario_packets(spec: ScenarioSpec) -> list[PacketInfo]:
    """Convert a scenario script into ``PacketInfo`` packets (script-relative timestamps)."""
    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + p.offset_s,
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            src_port=p.src_port,
            dst_port=p.dst_port,
            protocol=6,
            packet_length=p.length,
            is_tcp=True,
            syn=p.syn,
            ack=p.ack,
            rst=p.rst,
            fin=p.fin,
        )
        for p in spec.packets
    ]


def get_scenario(scenario_id: str) -> ScenarioSpec | None:
    """Return the scenario with ``scenario_id`` or ``None``."""
    return SCENARIOS.get(scenario_id)


def scenario_metadata(spec: ScenarioSpec) -> dict:
    """JSON-serialisable scenario descriptor for the dashboard API."""
    return {
        "id": spec.id,
        "name": spec.name,
        "description": spec.description,
        "category": spec.category,
        "attacker_ip": spec.attacker_ip,
        "victim_ip": VICTIM_IP,
        "src_port": spec.src_port,
        "dst_port": spec.dst_port,
        "packet_count": spec.packet_count,
        "expected_flows": spec.expected_flows,
        "duration_s": round(spec.duration_s, 3),
        "expected_score": spec.expected_score,
        "expected_band": spec.expected_band,
        "calibration_note": spec.calibration_note,
        "calibration_model": CALIBRATION_MODEL,
    }


def list_scenarios() -> list[dict]:
    """All scenarios in declared order (detected scenarios first, evasion demos last)."""
    return [scenario_metadata(spec) for spec in SCENARIOS.values()]
