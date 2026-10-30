"""Deterministic security rule engine for fast, policy-based network intrusion detection.

Provides deterministic detection of known attacks and policy violations
independently of machine-learning models. Rules are explicit, deterministic,
testable, and have zero dependencies on model weights or heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:
    from xrlids.demo.flow import Flow


@dataclass(frozen=True)
class RuleMatch:
    """Represents a single deterministic rule match."""

    rule_id: str
    name: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str
    matched_value: str


@dataclass
class SecurityRule:
    """Specification of a deterministic detection rule."""

    rule_id: str
    name: str
    severity: str
    description: str
    evaluator: Callable[[Flow], RuleMatch | None]

    def evaluate(self, flow: Flow) -> RuleMatch | None:
        """Evaluate rule against a Flow instance."""
        return self.evaluator(flow)


def _eval_tcp_invalid_flags(flow: Flow) -> RuleMatch | None:
    """RULE-TCP-INVALID-FLAGS: Check for illegal TCP control flag combinations (RFC 793/1122)."""
    if flow.key.protocol != 6:
        return None

    if getattr(flow, "has_syn_fin", False):
        return RuleMatch(
            rule_id="RULE-TCP-INVALID-FLAGS",
            name="TCP Invalid Flags (SYN+FIN)",
            severity="HIGH",
            description="RFC 793 violation: simultaneous SYN and FIN flags set (stealth/fingerprint probe).",
            matched_value="SYN+FIN",
        )
    if getattr(flow, "has_syn_rst", False):
        return RuleMatch(
            rule_id="RULE-TCP-INVALID-FLAGS",
            name="TCP Invalid Flags (SYN+RST)",
            severity="HIGH",
            description="Invalid TCP state: simultaneous SYN and RST flags set.",
            matched_value="SYN+RST",
        )
    if getattr(flow, "has_xmas_flags", False):
        return RuleMatch(
            rule_id="RULE-TCP-INVALID-FLAGS",
            name="TCP Xmas Scan Flags",
            severity="HIGH",
            description="Stealth scan signature: Xmas scan (FIN, PSH, and URG flags all set).",
            matched_value="FIN+PSH+URG",
        )
    if getattr(flow, "has_null_flags", False):
        return RuleMatch(
            rule_id="RULE-TCP-INVALID-FLAGS",
            name="TCP NULL Scan Flags",
            severity="HIGH",
            description="Stealth scan signature: NULL scan (zero control flags in TCP packet).",
            matched_value="NULL (flags=0)",
        )
    if getattr(flow, "invalid_flags_count", 0) > 0:
        return RuleMatch(
            rule_id="RULE-TCP-INVALID-FLAGS",
            name="TCP Invalid Flag Anomaly",
            severity="HIGH",
            description=f"Illegal TCP flag combination encountered ({flow.invalid_flags_count} packet(s)).",
            matched_value=f"invalid_flags_count={flow.invalid_flags_count}",
        )
    return None


def _eval_syn_flood(flow: Flow) -> RuleMatch | None:
    """RULE-SYN-FLOOD: Check for unanswered or extreme SYN flood patterns."""
    if flow.key.protocol != 6:
        return None

    syn = flow.syn_count
    ack = flow.ack_count

    # High SYN count with zero ACK response
    if syn >= 20 and ack == 0:
        return RuleMatch(
            rule_id="RULE-SYN-FLOOD",
            name="TCP SYN Flood (Zero ACK)",
            severity="HIGH",
            description=f"Unidirectional SYN flood: {syn} SYN packet(s) with 0 ACK response.",
            matched_value=f"syn_count={syn}, ack_count={ack}",
        )

    # Disproportionate SYN-to-ACK ratio with substantial volume
    if syn >= 10:
        ratio = syn / max(ack, 1.0)
        if ratio >= 10.0:
            return RuleMatch(
                rule_id="RULE-SYN-FLOOD",
                name="TCP SYN Flood (High SYN/ACK Ratio)",
                severity="HIGH",
                description=f"Disproportionate SYN-to-ACK ratio: {syn} SYNs to {ack} ACKs (ratio={ratio:.1f}).",
                matched_value=f"syn_count={syn}, ack_count={ack}, ratio={ratio:.2f}",
            )

    return None


def _eval_port_scan(flow: Flow) -> RuleMatch | None:
    """RULE-PORT-SCAN: Check for single-flow port scan probe signatures."""
    if flow.key.protocol != 6:
        return None

    syn = flow.syn_count
    ack = flow.ack_count
    total_bytes = flow.total_bytes

    # Repeated probe packets with minimal/zero payload
    if syn >= 5 and total_bytes <= 250:
        return RuleMatch(
            rule_id="RULE-PORT-SCAN",
            name="TCP Port Scan Probe",
            severity="MEDIUM",
            description=f"Rapid port probe signature: {syn} SYNs with only {total_bytes} total bytes.",
            matched_value=f"syn_count={syn}, total_bytes={total_bytes}",
        )

    if syn >= 3 and ack == 0 and total_bytes <= 180:
        return RuleMatch(
            rule_id="RULE-PORT-SCAN",
            name="TCP Unanswered Port Probe",
            severity="MEDIUM",
            description=f"Unanswered probe signature: {syn} SYNs, 0 ACKs, {total_bytes} total bytes.",
            matched_value=f"syn_count={syn}, ack_count=0, total_bytes={total_bytes}",
        )

    return None


def _eval_high_rate_burst(flow: Flow) -> RuleMatch | None:
    """RULE-HIGH-RATE-BURST: Check for extreme volumetric packet or byte bursts."""
    if flow.packet_count < 10 or flow.duration_s <= 0.0:
        return None

    dur_s = max(flow.duration_s, 1e-6)
    pps = flow.packet_count / dur_s
    bps = flow.total_bytes / dur_s

    if pps >= 50000.0:
        return RuleMatch(
            rule_id="RULE-HIGH-RATE-BURST",
            name="High Volumetric Packet Rate Burst",
            severity="HIGH",
            description=f"Extreme packet rate burst: {pps:.1f} pkts/s (threshold: 50,000 pkts/s).",
            matched_value=f"flow_packets_per_s={pps:.1f}",
        )

    if bps >= 50000000.0:  # 50 MB/s per single flow
        return RuleMatch(
            rule_id="RULE-HIGH-RATE-BURST",
            name="High Volumetric Byte Rate Burst",
            severity="HIGH",
            description=f"Extreme byte rate burst: {bps / 1e6:.1f} MB/s (threshold: 50 MB/s).",
            matched_value=f"flow_bytes_per_s={bps:.1f}",
        )

    return None


def _eval_ip_spoof_reserved(flow: Flow) -> RuleMatch | None:
    """RULE-IP-SPOOF-RESERVED: Check for illegal or reserved source IP addresses."""
    src_ip = flow.source_first_ip.strip()
    dst_ip = flow.dest_first_ip.strip()

    if not src_ip:
        return None

    if src_ip in ("0.0.0.0", "255.255.255.255") and flow.key.protocol == 6:
        return RuleMatch(
            rule_id="RULE-IP-SPOOF-RESERVED",
            name="Reserved/Broadcast Source IP on TCP",
            severity="HIGH",
            description=f"Illegal source IP {src_ip} initiating TCP connection (RFC 1122).",
            matched_value=f"src_ip={src_ip}",
        )

    # Loopback address emitted toward external non-loopback destination
    if src_ip.startswith("127.") and not dst_ip.startswith("127."):
        return RuleMatch(
            rule_id="RULE-IP-SPOOF-RESERVED",
            name="Cross-Interface Loopback Spoofing",
            severity="HIGH",
            description=f"Spoofed loopback source IP {src_ip} directed to external destination {dst_ip}.",
            matched_value=f"src_ip={src_ip}, dst_ip={dst_ip}",
        )

    return None


def _eval_icmp_flood(flow: Flow) -> RuleMatch | None:
    """RULE-ICMP-FLOOD: Check for ICMP echo burst or high-rate ICMP volume."""
    if flow.key.protocol != 1:
        return None

    if flow.packet_count >= 20:
        return RuleMatch(
            rule_id="RULE-ICMP-FLOOD",
            name="ICMP Burst / Flood",
            severity="MEDIUM",
            description=f"High-volume ICMP traffic burst: {flow.packet_count} packets in single flow.",
            matched_value=f"packet_count={flow.packet_count}, protocol=ICMP",
        )

    dur_s = max(flow.duration_s, 1e-6)
    pps = flow.packet_count / dur_s
    if flow.packet_count >= 10 and pps >= 20.0:
        return RuleMatch(
            rule_id="RULE-ICMP-FLOOD",
            name="ICMP High-Rate Echo Burst",
            severity="MEDIUM",
            description=f"High-rate ICMP echo burst: {pps:.1f} pkts/s (threshold: 20 pkts/s).",
            matched_value=f"flow_packets_per_s={pps:.1f}, protocol=ICMP",
        )

    return None


class RuleEngine:
    """Deterministic, policy-based detection engine executing deterministic network rules."""

    def __init__(self, rules: Sequence[SecurityRule] | None = None) -> None:
        if rules is None:
            self.rules = self.get_default_rules()
        else:
            self.rules = list(rules)

    @classmethod
    def get_default_rules(cls) -> list[SecurityRule]:
        """Return the standard suite of deterministic security rules."""
        return [
            SecurityRule(
                rule_id="RULE-TCP-INVALID-FLAGS",
                name="TCP Invalid Control Flags",
                severity="HIGH",
                description="Checks for RFC 793/1122 violations and stealth scan flags (SYN+FIN, SYN+RST, Xmas, NULL).",
                evaluator=_eval_tcp_invalid_flags,
            ),
            SecurityRule(
                rule_id="RULE-SYN-FLOOD",
                name="TCP SYN Flood Detection",
                severity="HIGH",
                description="Checks for unidirectional SYN bursts or extreme SYN/ACK asymmetry.",
                evaluator=_eval_syn_flood,
            ),
            SecurityRule(
                rule_id="RULE-PORT-SCAN",
                name="Port Scan Probe Detection",
                severity="MEDIUM",
                description="Checks for rapid probe flows characterized by low byte count and repeated SYNs.",
                evaluator=_eval_port_scan,
            ),
            SecurityRule(
                rule_id="RULE-HIGH-RATE-BURST",
                name="Volumetric High-Rate Burst",
                severity="HIGH",
                description="Checks for volumetric bursts exceeding 50,000 pkts/s or 50 MB/s.",
                evaluator=_eval_high_rate_burst,
            ),
            SecurityRule(
                rule_id="RULE-IP-SPOOF-RESERVED",
                name="Reserved / Spoofed Source IP",
                severity="HIGH",
                description="Checks for invalid source addresses including 0.0.0.0 on TCP or cross-interface loopback.",
                evaluator=_eval_ip_spoof_reserved,
            ),
            SecurityRule(
                rule_id="RULE-ICMP-FLOOD",
                name="ICMP Echo Burst / Flood",
                severity="MEDIUM",
                description="Checks for volumetric ICMP echo floods exceeding 20 packets or 20 pkts/s.",
                evaluator=_eval_icmp_flood,
            ),
        ]

    def evaluate_flow(self, flow: Flow) -> list[RuleMatch]:
        """Evaluate all registered rules against a completed Flow object."""
        matches: list[RuleMatch] = []
        for rule in self.rules:
            match = rule.evaluate(flow)
            if match is not None:
                matches.append(match)
        return matches

    def evaluate_features(
        self,
        features: dict[str, float],
        endpoints: dict[str, str] | None = None,
    ) -> list[RuleMatch]:
        """Evaluate deterministic rules against a feature dictionary where raw Flow is unavailable.

        Used for offline CSV datasets and feature vectors.
        """
        matches: list[RuleMatch] = []

        # RULE-SYN-FLOOD from features
        syn = float(features.get("syn_count", 0.0))
        ack = float(features.get("ack_count", 0.0))
        syn_ack = float(features.get("syn_ack_ratio", 0.0))

        if syn >= 20.0 and ack == 0.0:
            matches.append(
                RuleMatch(
                    rule_id="RULE-SYN-FLOOD",
                    name="TCP SYN Flood (Zero ACK)",
                    severity="HIGH",
                    description=f"Unidirectional SYN flood: {int(syn)} SYNs with 0 ACKs.",
                    matched_value=f"syn_count={int(syn)}, ack_count={int(ack)}",
                )
            )
        elif syn >= 10.0 and (syn_ack >= 10.0 or (ack > 0 and syn / ack >= 10.0)):
            matches.append(
                RuleMatch(
                    rule_id="RULE-SYN-FLOOD",
                    name="TCP SYN Flood (High SYN/ACK Ratio)",
                    severity="HIGH",
                    description=f"Disproportionate SYN-to-ACK ratio: {int(syn)} SYNs to {int(ack)} ACKs.",
                    matched_value=f"syn_count={int(syn)}, ack_count={int(ack)}, ratio={syn_ack:.2f}",
                )
            )

        # RULE-PORT-SCAN from features
        mean_len = float(features.get("packet_length_mean", 100.0))
        if syn >= 5.0 and mean_len <= 60.0 and ack == 0.0:
            matches.append(
                RuleMatch(
                    rule_id="RULE-PORT-SCAN",
                    name="TCP Port Scan Probe",
                    severity="MEDIUM",
                    description=f"Port scan probe signature: {int(syn)} SYNs with small packet mean {mean_len:.1f} bytes.",
                    matched_value=f"syn_count={int(syn)}, packet_length_mean={mean_len:.1f}",
                )
            )

        # RULE-HIGH-RATE-BURST from features
        pps = float(features.get("flow_packets_per_s", 0.0))
        bps = float(features.get("flow_bytes_per_s", 0.0))
        if pps >= 50000.0:
            matches.append(
                RuleMatch(
                    rule_id="RULE-HIGH-RATE-BURST",
                    name="High Volumetric Packet Rate Burst",
                    severity="HIGH",
                    description=f"Extreme packet rate burst: {pps:.1f} pkts/s (threshold: 50,000 pkts/s).",
                    matched_value=f"flow_packets_per_s={pps:.1f}",
                )
            )
        elif bps >= 50000000.0:
            matches.append(
                RuleMatch(
                    rule_id="RULE-HIGH-RATE-BURST",
                    name="High Volumetric Byte Rate Burst",
                    severity="HIGH",
                    description=f"Extreme byte rate burst: {bps / 1e6:.1f} MB/s (threshold: 50 MB/s).",
                    matched_value=f"flow_bytes_per_s={bps:.1f}",
                )
            )

        # RULE-IP-SPOOF-RESERVED if endpoints dict provided
        if endpoints:
            src_ip = endpoints.get("src_ip", "").strip()
            dst_ip = endpoints.get("dst_ip", "").strip()
            if src_ip in ("0.0.0.0", "255.255.255.255"):
                matches.append(
                    RuleMatch(
                        rule_id="RULE-IP-SPOOF-RESERVED",
                        name="Reserved/Broadcast Source IP on TCP",
                        severity="HIGH",
                        description=f"Illegal source IP {src_ip} initiating connection.",
                        matched_value=f"src_ip={src_ip}",
                    )
                )
            elif src_ip.startswith("127.") and not dst_ip.startswith("127."):
                matches.append(
                    RuleMatch(
                        rule_id="RULE-IP-SPOOF-RESERVED",
                        name="Cross-Interface Loopback Spoofing",
                        severity="HIGH",
                        description=f"Spoofed loopback source IP {src_ip} targeting {dst_ip}.",
                        matched_value=f"src_ip={src_ip}, dst_ip={dst_ip}",
                    )
                )

        return matches

    def list_rules(self) -> list[dict[str, Any]]:
        """Return serializable summary of all registered rules."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity,
                "description": r.description,
            }
            for r in self.rules
        ]
