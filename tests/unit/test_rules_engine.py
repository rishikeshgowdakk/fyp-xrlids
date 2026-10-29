"""Unit tests for the deterministic rule engine (src/xrlids/rules/engine.py).

Verifies deterministic security rules, positive/negative match criteria,
and strict distinction between rule detections and ML Random Forest predictions.
"""

from __future__ import annotations

import numpy as np
import pytest

from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.live_lab import AlertEvent, FlowObservation, LiveLabMonitor
from xrlids.demo.pcap import PacketInfo
from xrlids.demo.replay import ReplayEngine
from xrlids.rules.engine import RuleEngine, RuleMatch, SecurityRule


class _MockModel:
    """Mock detector returning a fixed attack probability for testing."""

    def __init__(self, score: float = 0.10) -> None:
        self.score = score

    def predict_proba(self, X) -> np.ndarray:
        p = self.score
        return np.array([[1.0 - p, p]] * len(X))


def _make_tcp_flow(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 80,
    syn_count: int = 1,
    ack_count: int = 1,
    rst_count: int = 0,
    fin_count: int = 0,
    total_bytes: int = 500,
    duration_s: float = 1.0,
    has_syn_fin: bool = False,
    has_syn_rst: bool = False,
    has_xmas: bool = False,
    has_null: bool = False,
    invalid_flags_count: int = 0,
) -> Flow:
    key = FlowKey(src_ip, dst_ip, src_port, dst_port, 6)
    fl = Flow(
        key=key,
        start_time=100.0,
        last_time=100.0 + max(duration_s, 0.0),
        packet_lengths=[total_bytes // max(syn_count + ack_count, 1)] * max(syn_count + ack_count, 1),
        total_bytes=total_bytes,
        syn_count=syn_count,
        ack_count=ack_count,
        rst_count=rst_count,
        fin_count=fin_count,
        source_first_ip=src_ip,
        source_first_port=src_port,
        dest_first_ip=dst_ip,
        dest_first_port=dst_port,
        has_syn_fin=has_syn_fin,
        has_syn_rst=has_syn_rst,
        has_xmas_flags=has_xmas,
        has_null_flags=has_null,
        invalid_flags_count=invalid_flags_count,
    )
    return fl


def test_rule_tcp_invalid_flags_matches():
    """Verify RULE-TCP-INVALID-FLAGS triggers on RFC 793/1122 violations."""
    engine = RuleEngine()

    # Normal flow: no invalid flags
    normal_fl = _make_tcp_flow(syn_count=2, ack_count=2)
    matches = engine.evaluate_flow(normal_fl)
    assert not any(m.rule_id == "RULE-TCP-INVALID-FLAGS" for m in matches)

    # SYN+FIN
    syn_fin_fl = _make_tcp_flow(has_syn_fin=True)
    matches = engine.evaluate_flow(syn_fin_fl)
    match_ids = [m.rule_id for m in matches]
    assert "RULE-TCP-INVALID-FLAGS" in match_ids
    match = next(m for m in matches if m.rule_id == "RULE-TCP-INVALID-FLAGS")
    assert match.severity == "HIGH"
    assert "SYN+FIN" in match.matched_value

    # Xmas scan (FIN+PSH+URG)
    xmas_fl = _make_tcp_flow(has_xmas=True)
    matches = engine.evaluate_flow(xmas_fl)
    assert any(m.rule_id == "RULE-TCP-INVALID-FLAGS" for m in matches)

    # NULL scan (zero flags)
    null_fl = _make_tcp_flow(has_null=True)
    matches = engine.evaluate_flow(null_fl)
    assert any(m.rule_id == "RULE-TCP-INVALID-FLAGS" for m in matches)

    # SYN+RST
    syn_rst_fl = _make_tcp_flow(has_syn_rst=True)
    matches = engine.evaluate_flow(syn_rst_fl)
    assert any(m.rule_id == "RULE-TCP-INVALID-FLAGS" for m in matches)


def test_rule_syn_flood_matches():
    """Verify RULE-SYN-FLOOD identifies unidirectional or disproportionate SYN bursts."""
    engine = RuleEngine()

    # Normal flow with balanced SYNs and ACKs
    normal_fl = _make_tcp_flow(syn_count=5, ack_count=5)
    assert not any(m.rule_id == "RULE-SYN-FLOOD" for m in engine.evaluate_flow(normal_fl))

    # Unanswered SYN flood (>= 20 SYNs, 0 ACKs)
    flood_fl = _make_tcp_flow(syn_count=25, ack_count=0)
    matches = engine.evaluate_flow(flood_fl)
    assert any(m.rule_id == "RULE-SYN-FLOOD" for m in matches)
    match = next(m for m in matches if m.rule_id == "RULE-SYN-FLOOD")
    assert match.severity == "HIGH"
    assert "25" in match.matched_value

    # Disproportionate ratio (15 SYNs, 1 ACK -> ratio 15.0 >= 10.0)
    ratio_fl = _make_tcp_flow(syn_count=15, ack_count=1)
    matches = engine.evaluate_flow(ratio_fl)
    assert any(m.rule_id == "RULE-SYN-FLOOD" for m in matches)


def test_rule_port_scan_matches():
    """Verify RULE-PORT-SCAN detects low-volume rapid probes."""
    engine = RuleEngine()

    # Normal data transfer
    normal_fl = _make_tcp_flow(syn_count=2, ack_count=2, total_bytes=5000)
    assert not any(m.rule_id == "RULE-PORT-SCAN" for m in engine.evaluate_flow(normal_fl))

    # Port probe with repeated SYNs and minimal bytes
    probe_fl = _make_tcp_flow(syn_count=6, ack_count=0, total_bytes=150)
    matches = engine.evaluate_flow(probe_fl)
    assert any(m.rule_id == "RULE-PORT-SCAN" for m in matches)
    match = next(m for m in matches if m.rule_id == "RULE-PORT-SCAN")
    assert match.severity == "MEDIUM"


def test_rule_high_rate_burst_matches():
    """Verify RULE-HIGH-RATE-BURST catches extreme rate anomalies."""
    engine = RuleEngine()

    # Pps burst: 100 packets in 0.001s = 100,000 pkts/s (threshold 50,000)
    key = FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    burst_fl = Flow(
        key=key,
        start_time=100.0,
        last_time=100.001,
        packet_lengths=[64] * 100,
        total_bytes=6400,
        source_first_ip="10.0.0.1",
        dest_first_ip="10.0.0.2",
    )
    matches = engine.evaluate_flow(burst_fl)
    assert any(m.rule_id == "RULE-HIGH-RATE-BURST" for m in matches)

    # Normal pacing: 10 packets over 1.0s = 10 pkts/s
    normal_fl = Flow(
        key=key,
        start_time=100.0,
        last_time=101.0,
        packet_lengths=[64] * 10,
        total_bytes=640,
        source_first_ip="10.0.0.1",
        dest_first_ip="10.0.0.2",
    )
    assert not any(m.rule_id == "RULE-HIGH-RATE-BURST" for m in engine.evaluate_flow(normal_fl))


def test_rule_ip_spoof_reserved_matches():
    """Verify RULE-IP-SPOOF-RESERVED catches 0.0.0.0 and cross-interface loopback."""
    engine = RuleEngine()

    # Normal RFC 1918 flow
    normal_fl = _make_tcp_flow(src_ip="192.168.1.100", dst_ip="10.0.0.1")
    assert not any(m.rule_id == "RULE-IP-SPOOF-RESERVED" for m in engine.evaluate_flow(normal_fl))

    # Source 0.0.0.0 on TCP
    zero_fl = _make_tcp_flow(src_ip="0.0.0.0", dst_ip="192.168.1.1")
    matches = engine.evaluate_flow(zero_fl)
    assert any(m.rule_id == "RULE-IP-SPOOF-RESERVED" for m in matches)

    # Loopback source directed to external destination
    loopback_fl = _make_tcp_flow(src_ip="127.0.0.1", dst_ip="192.168.1.1")
    matches = engine.evaluate_flow(loopback_fl)
    assert any(m.rule_id == "RULE-IP-SPOOF-RESERVED" for m in matches)


def test_evaluate_features_offline():
    """Verify rule evaluation on feature dictionary (for offline CSVs)."""
    engine = RuleEngine()

    # SYN flood from features
    flood_feats = {
        "syn_count": 25.0,
        "ack_count": 0.0,
        "syn_ack_ratio": 25.0,
        "flow_packets_per_s": 50.0,
        "flow_bytes_per_s": 2000.0,
        "packet_length_mean": 60.0,
    }
    matches = engine.evaluate_features(flood_feats)
    assert any(m.rule_id == "RULE-SYN-FLOOD" for m in matches)

    # Normal features
    normal_feats = {
        "syn_count": 1.0,
        "ack_count": 1.0,
        "syn_ack_ratio": 1.0,
        "flow_packets_per_s": 10.0,
        "flow_bytes_per_s": 1000.0,
        "packet_length_mean": 100.0,
    }
    assert len(engine.evaluate_features(normal_feats)) == 0


def test_rule_detection_strictly_distinct_from_rf():
    """Verify that a rule match triggers an alert while preserving the real RF score without modification."""
    # Case 1: RF predicts BENIGN (conf=0.12), but flow matches RULE-SYN-FLOOD
    benign_rf = _MockModel(score=0.12)
    engine = ReplayEngine(model=benign_rf, threshold=0.50)
    monitor = LiveLabMonitor(engine=engine, alert_threshold=0.50)

    # Build packets for an unanswered SYN flood flow
    packets = [
        PacketInfo(100.0 + i * 0.01, "203.0.113.5", "192.168.10.50", 40000, 80, 6, 64, is_tcp=True, syn=True)
        for i in range(25)
    ]
    # Terminate with RST so flow completes
    packets.append(PacketInfo(100.30, "203.0.113.5", "192.168.10.50", 40000, 80, 6, 64, is_tcp=True, rst=True))

    alerts = monitor.process_packet_stream(iter(packets), mode="sample")

    # Alert must be emitted due to rule match
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_triggered is True
    assert "RULE-SYN-FLOOD" in alert.rule_matches
    assert alert.detection_source == "RULE"
    # CRITICAL: RF confidence is NOT fabricated or boosted; remains the real 0.12!
    assert alert.confidence == 0.12

    obs = monitor.observations[-1]
    assert obs.is_alert is True
    assert obs.detection_source == "RULE"
    assert obs.prediction_class == 0
    assert obs.prediction_label == "BENIGN"
    assert obs.attack_score == 0.12
    assert obs.rule_triggered is True
    assert "RULE-SYN-FLOOD" in obs.rule_matches


def test_rf_detection_without_rule_match():
    """Verify that a pure RF detection (e.g. conf=0.88) without rule match is labelled RF."""
    attack_rf = _MockModel(score=0.88)
    engine = ReplayEngine(model=attack_rf, threshold=0.50)
    monitor = LiveLabMonitor(engine=engine, alert_threshold=0.50)

    # Normal packet handshake (not matching any attack rule)
    packets = [
        PacketInfo(100.0, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 100, is_tcp=True, syn=True),
        PacketInfo(100.1, "10.0.0.1", "192.168.1.10", 80, 50000, 6, 100, is_tcp=True, syn=True, ack=True),
        PacketInfo(100.2, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 200, is_tcp=True, ack=True),
        PacketInfo(100.3, "192.168.1.10", "10.0.0.1", 50000, 80, 6, 64, is_tcp=True, fin=True),
    ]

    alerts = monitor.process_packet_stream(iter(packets), mode="live")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_triggered is False
    assert alert.rule_matches == []
    assert alert.detection_source == "RF"
    assert alert.confidence == 0.88

    obs = monitor.observations[-1]
    assert obs.is_alert is True
    assert obs.detection_source == "RF"
    assert obs.prediction_class == 1
    assert obs.prediction_label == "ATTACK"
    assert obs.attack_score == 0.88
    assert obs.rule_triggered is False


def test_hybrid_detection_when_both_rule_and_rf_trigger():
    """Verify HYBRID labelling when both deterministic rule and RF model detect attack."""
    attack_rf = _MockModel(score=0.95)
    engine = ReplayEngine(model=attack_rf, threshold=0.50)
    monitor = LiveLabMonitor(engine=engine, alert_threshold=0.50)

    # 25 SYNs (triggers RULE-SYN-FLOOD) with model predicting 0.95
    packets = [
        PacketInfo(100.0 + i * 0.01, "203.0.113.10", "192.168.10.50", 45000, 80, 6, 64, is_tcp=True, syn=True)
        for i in range(25)
    ]
    packets.append(PacketInfo(100.30, "203.0.113.10", "192.168.10.50", 45000, 80, 6, 64, is_tcp=True, rst=True))

    alerts = monitor.process_packet_stream(iter(packets), mode="sample")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_triggered is True
    assert "RULE-SYN-FLOOD" in alert.rule_matches
    assert alert.detection_source == "HYBRID"
    assert alert.confidence == 0.95

    obs = monitor.observations[-1]
    assert obs.detection_source == "HYBRID"
    assert obs.prediction_class == 1
    assert obs.prediction_label == "ATTACK"
    assert obs.rule_triggered is True


def test_zero_firewall_mutation_invariant():
    """Verify that rule evaluation never mutates system iptables or routing tables."""
    import subprocess
    from unittest.mock import patch

    with patch("subprocess.run") as mock_run:
        engine = RuleEngine()
        fl = _make_tcp_flow(has_syn_fin=True)
        engine.evaluate_flow(fl)

        # Confirm no subprocess was spawned to run iptables, nftables, or route
        mock_run.assert_not_called()
