"""Comprehensive unit test suite for Final Engineering Correctness, Security Rules, and Safety Guardrails."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xrlids.config.protected_assets import (
    AUTHORITATIVE_PROTECTED_REGISTRY,
    ProtectedAsset,
    ProtectedInfrastructureRegistry,
    is_critical_infrastructure,
)
from xrlids.demo.flow import Flow, FlowKey
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.service import DQNResponseService
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode
from xrlids.rules.correlation import MultiFlowPortScanCorrelator
from xrlids.rules.engine import RuleEngine
from xrlids.rules.hybrid import HybridDecisionEngine


# ==============================================================================
# GROUP A: DQN Causal State and Action Feedback (Section 2)
# ==============================================================================

def test_dqn_feedback_case_a_allow_approved():
    """Test A: DQN proposes ALLOW; safety approves ALLOW. History records ALLOW."""
    service = DQNResponseService()
    gate = DeterministicSafetyGate()

    # Step 1: recommend ALLOW
    rec = service.recommend_action(attack_score=0.02, flow_bytes_per_s=100.0, host_id="host-a")
    assert rec.action == Action.ALLOW

    # Safety gate approves ALLOW
    enforced, overridden, _ = gate.enforce_safety(step=0, flow_id=0, host_id="host-a", proposed_action=rec.action)
    assert enforced == Action.ALLOW
    assert overridden is False

    # Record actual enforced action
    service.record_enforced_action(host_id="host-a", attack_score=0.02, enforced_action=enforced)
    builder = service.get_host_builder("host-a")
    assert builder._last_action == Action.ALLOW

    # Step 2: Next state vector reflects previous enforced action ALLOW (value 0.0)
    next_s = builder.build_state(attack_score=0.05, flow_bytes_per_s=100.0)
    assert np.isclose(next_s[3], 0.0)


def test_dqn_feedback_case_b_isolate_overridden_to_alert():
    """Test B: DQN proposes ISOLATE; safety overrides to ALERT. History records ALERT, NOT ISOLATE."""
    service = DQNResponseService()
    gate = DeterministicSafetyGate()

    # Suppose DQN proposed ISOLATE against a critical gateway host
    proposed = Action.ISOLATE
    crit_host = "192.168.10.1"

    enforced, overridden, reason = gate.enforce_safety(step=0, flow_id=0, host_id=crit_host, proposed_action=proposed)
    assert enforced == Action.ALERT
    assert overridden is True
    assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"

    # Crucial correctness invariant: record the safety-enforced action, NEVER the rejected proposed action!
    service.record_enforced_action(host_id=crit_host, attack_score=0.95, enforced_action=enforced)
    builder = service.get_host_builder(crit_host)

    assert builder._last_action == Action.ALERT
    assert builder._last_action != Action.ISOLATE

    # Next state s3 must contain normalized ALERT (1/3 = 0.333), NOT ISOLATE (3/3 = 1.0)
    next_s = builder.build_state(attack_score=0.90, flow_bytes_per_s=5000.0)
    assert np.isclose(next_s[3], Action.ALERT.value / 3.0)
    assert not np.isclose(next_s[3], Action.ISOLATE.value / 3.0)


def test_dqn_feedback_case_c_3action_mode_clamped_to_rate_limit():
    """Test C: DQN proposes ISOLATE; 3-action mode clamps to RATE_LIMIT. History records RATE_LIMIT."""
    service = DQNResponseService()
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.THREE_ACTION)

    enforced, overridden, reason = gate.enforce_safety(step=0, flow_id=0, host_id="10.0.0.88", proposed_action=Action.ISOLATE)
    assert enforced == Action.RATE_LIMIT
    assert overridden is True
    assert reason == "ACTION_MODE_3_ACTION_CLAMP"

    service.record_enforced_action(host_id="10.0.0.88", attack_score=0.88, enforced_action=enforced)
    builder = service.get_host_builder("10.0.0.88")
    assert builder._last_action == Action.RATE_LIMIT

    # Next state s3 contains normalized RATE_LIMIT (2/3 = 0.667)
    next_s = builder.build_state(attack_score=0.70, flow_bytes_per_s=1000.0)
    assert np.isclose(next_s[3], Action.RATE_LIMIT.value / 3.0)


def test_dqn_feedback_case_d_cooldown_maintains_mitigation():
    """Test D: Policy proposes ALLOW during mandatory cooldown; gate preserves RATE_LIMIT. History records RATE_LIMIT."""
    gate = DeterministicSafetyGate(cooldown_steps=10)
    service = DQNResponseService()

    # Step 0: Apply RATE_LIMIT
    gate.enforce_safety(0, "f0", "host-d", Action.RATE_LIMIT)
    service.record_enforced_action("host-d", 0.85, Action.RATE_LIMIT, cooldown_remaining=10)

    # Step 4: Policy attempts to de-escalate to ALLOW while cooldown active
    enforced, overridden, reason = gate.enforce_safety(4, "f1", "host-d", Action.ALLOW)
    assert enforced == Action.RATE_LIMIT
    assert overridden is True
    assert reason == "MANDATORY_ACTION_COOLDOWN"

    service.record_enforced_action("host-d", 0.40, enforced, cooldown_remaining=6)
    builder = service.get_host_builder("host-d")
    assert builder._last_action == Action.RATE_LIMIT

    next_s = builder.build_state(attack_score=0.40, flow_bytes_per_s=100.0)
    assert np.isclose(next_s[3], Action.RATE_LIMIT.value / 3.0)


def test_dqn_feedback_case_e_pipeline_consecutive_flow_enforced_action():
    """Test E: In end-to-end pipeline, next flow observation strictly contains previous enforced action."""
    event_mgr = EventManager()
    pipeline = ActiveInferencePipeline(event_manager=event_mgr)

    r10_attack = {
        "flow_duration_ms": 500.0,
        "flow_packets_per_s": 5000.0,
        "flow_bytes_per_s": 300000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 0.0,
        "syn_count": 100.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 100.0,
    }

    # Flow 1 against critical gateway: proposed ISOLATE, but enforced ALERT
    res1 = pipeline.process_flow(
        r10_attack,
        source_ip="192.168.10.1",
        dest_ip="10.0.0.5",
        flow_id="f-test-1",
    )
    assert res1.enforced_action == Action.ALERT
    assert res1.safety_override is True

    # Check StateBuilder internal memory
    builder = pipeline.response_service.get_host_builder("192.168.10.1")
    assert builder._last_action == Action.ALERT

    # Flow 2 from same host: build state, verify s3 reflects Action.ALERT (0.333), not ISOLATE (1.0)
    res2 = pipeline.process_flow(
        r10_attack,
        source_ip="192.168.10.1",
        dest_ip="10.0.0.5",
        flow_id="f-test-2",
    )
    assert np.isclose(res2.response.state_vector[3], Action.ALERT.value / 3.0)


def test_dqn_feedback_case_f_history_does_not_advance_on_failure():
    """Test F: Verify history does not advance when execution fails before finalization."""
    service = DQNResponseService()
    builder = service.get_host_builder("host-fail")

    # Initial clean history
    assert len(builder._score_history) == 0
    assert builder._last_action == Action.ALLOW

    # Recommend action without auto_update_history
    rec = service.recommend_action(attack_score=0.95, flow_bytes_per_s=1000.0, host_id="host-fail")
    assert rec.action in (Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE)

    # Simulated crash before record_enforced_action: verify history was NOT advanced
    assert len(builder._score_history) == 0
    assert builder._last_action == Action.ALLOW


# ==============================================================================
# GROUP B: Monotonic Time-Based Cooldown (Section 3)
# ==============================================================================

def test_time_based_cooldown_monotonic_progression():
    """Verify time-based cooldown tracks actual elapsed seconds independently of flow count."""
    simulated_time = 100.0

    def mock_clock() -> float:
        return simulated_time

    gate = DeterministicSafetyGate(cooldown_seconds_duration=30.0, clock=mock_clock)

    # t = 100.0: Apply RATE_LIMIT
    enforced1, _, _ = gate.enforce_safety(step=0, flow_id="f1", host_id="10.0.0.10", proposed_action=Action.RATE_LIMIT)
    assert enforced1 == Action.RATE_LIMIT
    assert gate.get_remaining_cooldown_seconds("10.0.0.10") == pytest.approx(30.0)
    assert gate.get_remaining_cooldown_fraction("10.0.0.10") == pytest.approx(1.0)

    # t = 115.0: 15 seconds elapsed, 15 seconds remaining
    simulated_time = 115.0
    assert gate.get_remaining_cooldown_seconds("10.0.0.10") == pytest.approx(15.0)
    assert gate.get_remaining_cooldown_fraction("10.0.0.10") == pytest.approx(0.50)

    # Attempt ALLOW: cooldown prevents violent de-escalation
    enforced2, overridden2, reason2 = gate.enforce_safety(step=1, flow_id="f2", host_id="10.0.0.10", proposed_action=Action.ALLOW)
    assert enforced2 == Action.RATE_LIMIT
    assert overridden2 is True
    assert reason2 == "MANDATORY_ACTION_COOLDOWN"

    # t = 130.1: Cooldown expired (> 30s elapsed)
    simulated_time = 130.1
    assert gate.get_remaining_cooldown_seconds("10.0.0.10") == 0.0
    assert gate.get_remaining_cooldown_fraction("10.0.0.10") == 0.0

    # ALLOW now approved cleanly
    enforced3, overridden3, _ = gate.enforce_safety(step=2, flow_id="f3", host_id="10.0.0.10", proposed_action=Action.ALLOW)
    assert enforced3 == Action.ALLOW
    assert overridden3 is False


def test_high_volume_traffic_cannot_bypass_cooldown():
    """Verify 100 rapid flows in 1 second do not exhaust the 30-second cooldown."""
    simulated_time = 200.0
    gate = DeterministicSafetyGate(cooldown_seconds_duration=30.0, clock=lambda: simulated_time)

    # Enforce ISOLATE
    gate.enforce_safety(0, "f0", "victim-host", Action.ISOLATE)

    # Send 100 flows within 1.0 second (simulated_time advances by 0.01s each flow)
    for i in range(1, 101):
        simulated_time += 0.01
        enforced, overridden, _ = gate.enforce_safety(i, f"f{i}", "victim-host", Action.ALLOW)
        # MUST remain in cooldown: 201.0 is still well within [200.0, 230.0]
        assert enforced == Action.ISOLATE
        assert overridden is True


def test_slow_traffic_does_not_extend_cooldown_indefinitely():
    """Verify slow traffic (1 flow every 10s) expires naturally after 30s rather than 30 flows."""
    simulated_time = 500.0
    gate = DeterministicSafetyGate(cooldown_seconds_duration=30.0, clock=lambda: simulated_time)

    # Flow 1 at t=500.0: RATE_LIMIT
    gate.enforce_safety(0, "f0", "slow-host", Action.RATE_LIMIT)

    # Flow 2 at t=510.0 (10s elapsed): in cooldown
    simulated_time = 510.0
    enforced2, ov2, _ = gate.enforce_safety(1, "f1", "slow-host", Action.ALLOW)
    assert enforced2 == Action.RATE_LIMIT
    assert ov2 is True

    # Flow 3 at t=545.0 (45s elapsed > 30s): expired! Only 2 flows occurred, but cooldown expired by time
    simulated_time = 545.0
    enforced3, ov3, _ = gate.enforce_safety(2, "f2", "slow-host", Action.ALLOW)
    assert enforced3 == Action.ALLOW
    assert ov3 is False


# ==============================================================================
# GROUP C: Authoritative Critical Infrastructure Protection (Section 4)
# ==============================================================================

def test_protected_infrastructure_authoritative_config():
    """Verify authoritative registry correctly matches gateway, DNS, and IP formats."""
    registry = ProtectedInfrastructureRegistry()

    # Explicitly protected gateway and DNS
    assert registry.is_protected("192.168.10.1")
    assert registry.is_protected("192.168.10.2")
    assert registry.is_protected("gateway")
    assert registry.is_protected("dns")
    assert registry.is_protected("core-router")

    # Ordinary endpoints are NOT protected
    assert not registry.is_protected("10.0.0.99")
    assert not registry.is_protected("192.168.1.155")

    # Unrecognised hostnames and malformed IPs handled safely without raising exceptions
    assert not registry.is_protected("random-malicious-host")
    assert not registry.is_protected("999.999.999.999")
    assert not registry.is_protected("invalid_ip_format")
    assert not registry.is_protected("")


def test_critical_host_can_never_be_isolated():
    """Verify DeterministicSafetyGate prevents isolation of any authoritative protected asset."""
    gate = DeterministicSafetyGate()

    critical_test_cases = [
        "192.168.10.1",   # Core Gateway
        "192.168.10.2",   # Core DNS
        "192.168.10.50",  # Domain Controller
        "gateway",
        "dns",
    ]

    for host in critical_test_cases:
        enforced, overridden, reason = gate.enforce_safety(0, "f-crit", host, Action.ISOLATE)
        assert enforced == Action.ALERT, f"Host {host} must be downgraded to ALERT"
        assert overridden is True
        assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"


def test_custom_deployment_protected_host_via_env(monkeypatch):
    """Verify custom protected host added via XRLIDS_CRITICAL_HOSTS cannot be isolated."""
    monkeypatch.setenv("XRLIDS_CRITICAL_HOSTS", "10.50.0.1,corporate-vault")
    custom_reg = ProtectedInfrastructureRegistry()

    assert custom_reg.is_protected("10.50.0.1")
    assert custom_reg.is_protected("corporate-vault")
    assert not custom_reg.is_protected("10.50.0.2")


# ==============================================================================
# GROUP D: Multi-Flow Port Scan Correlation (Section 5)
# ==============================================================================

def test_multi_flow_port_scan_vertical():
    """Verify 5-port scan against a single destination triggers multi-flow port scan rule."""
    correlator = MultiFlowPortScanCorrelator(window_seconds=60.0, min_unique_ports=5, min_probes=5)

    source_ip = "192.168.1.105"
    target_ip = "10.0.0.20"
    target_ports = [21, 22, 23, 80, 443]

    res = None
    for port in target_ports:
        res = correlator.record_probe(
            source_ip=source_ip,
            dest_ip=target_ip,
            dest_port=port,
            timestamp=100.0,
            is_syn=True,
        )

    assert res is not None
    assert res.is_port_scan is True
    assert res.unique_ports_count == 5
    assert res.scan_type == "VERTICAL"
    assert res.rule_id == "RULE-PORT-SCAN-MULTI-FLOW"
    assert res.severity == "HIGH"


def test_multi_flow_port_scan_distributed():
    """Verify distributed horizontal port scan across different hosts triggers."""
    correlator = MultiFlowPortScanCorrelator(window_seconds=60.0, min_unique_ports=5, min_probes=5)

    source_ip = "192.168.1.200"
    # Scan 5 distinct targets on 5 distinct ports
    probes = [("10.0.0.1", 80), ("10.0.0.2", 443), ("10.0.0.3", 8080), ("10.0.0.4", 22), ("10.0.0.5", 3389)]

    res = None
    for dst, port in probes:
        res = correlator.record_probe(source_ip, dst, port, timestamp=50.0)

    assert res is not None
    assert res.is_port_scan is True
    assert res.scan_type == "DISTRIBUTED"
    assert res.unique_ports_count == 5


def test_normal_traffic_does_not_trigger_multi_flow_port_scan():
    """Verify client repeatedly connecting to 2 standard services (80, 443) does not trigger."""
    correlator = MultiFlowPortScanCorrelator(window_seconds=60.0, min_unique_ports=5, min_probes=5)

    # 20 requests to ports 80 and 443
    for i in range(20):
        port = 80 if i % 2 == 0 else 443
        res = correlator.record_probe("192.168.1.50", "142.250.190.46", port, timestamp=10.0 + i)
        assert res is None, "Normal traffic to 2 ports must never trigger port scan"


def test_multi_flow_port_scan_expired_window():
    """Verify probes outside correlation window expire and do not trigger."""
    correlator = MultiFlowPortScanCorrelator(window_seconds=30.0, min_unique_ports=5, min_probes=5)

    # 3 probes at t = 10.0
    for p in [21, 22, 23]:
        correlator.record_probe("10.0.0.5", "10.0.0.1", p, timestamp=10.0)

    # 2 probes at t = 50.0 (40s elapsed > 30s window; old probes expired)
    res = None
    for p in [80, 443]:
        res = correlator.record_probe("10.0.0.5", "10.0.0.1", p, timestamp=50.0)

    assert res is None, "Expired probes must not accumulate across window boundaries"


def test_multi_flow_port_scan_out_of_order_timestamps():
    """Verify out-of-order packet timestamps are handled gracefully."""
    correlator = MultiFlowPortScanCorrelator(window_seconds=60.0, min_unique_ports=5, min_probes=5)

    # Probes arriving with slight timestamp jitter: 102, 100, 105, 101, 103
    timestamps_ports = [(102.0, 80), (100.0, 22), (105.0, 443), (101.0, 21), (103.0, 8080)]
    res = None
    for ts, p in timestamps_ports:
        res = correlator.record_probe("10.0.0.7", "10.0.0.1", p, timestamp=ts)

    assert res is not None
    assert res.is_port_scan is True


def test_multi_flow_port_scan_bounded_memory():
    """Verify LRU pruning enforces max_tracked_sources bound."""
    correlator = MultiFlowPortScanCorrelator(max_tracked_sources=20, min_unique_ports=5)

    # Insert 50 distinct sources
    for i in range(50):
        correlator.record_probe(f"192.168.1.{i}", "10.0.0.1", 80, timestamp=10.0)

    assert len(correlator._sources) <= 20, "Correlator sources must remain strictly bounded"


# ==============================================================================
# GROUP E: Security Rules & Missing Feature Auditing (Section 6 & 7)
# ==============================================================================

def test_missing_features_recorded_and_not_silently_zero_filled():
    """Verify missing features mark rules as unavailable rather than creating false benign conclusions."""
    engine = RuleEngine()

    # Degraded feature dictionary (missing syn_count and ack_count)
    partial_feats = {
        "flow_duration_ms": 100.0,
        "packet_length_mean": 60.0,
    }

    matches, unavail_feats, unavail_rules = engine.evaluate_features_detailed(partial_feats)

    assert "RULE-SYN-FLOOD" in unavail_rules
    assert "syn_count" in unavail_feats
    assert "ack_count" in unavail_feats


def test_hybrid_decision_score_and_source_isolation():
    """Verify RF probability remains unchanged and rule severity floors only affect hybrid_risk_score."""
    hybrid = HybridDecisionEngine()

    # Case 1: Pure RF detection (prob 0.85, no rules)
    dec_rf = hybrid.evaluate(rf_probability=0.85, rule_matches=[])
    assert dec_rf.detection_source == "RF"
    assert dec_rf.rf_probability == pytest.approx(0.85)
    assert dec_rf.hybrid_risk_score == pytest.approx(0.85)

    # Case 2: Pure Rule detection (prob 0.05, Rule HIGH)
    from xrlids.rules.engine import RuleMatch
    rule_m = RuleMatch(
        rule_id="RULE-SYN-FLOOD",
        name="TCP SYN Flood",
        severity="HIGH",
        description="SYN Flood detected",
        matched_value="syn=100",
    )
    dec_rule = hybrid.evaluate(rf_probability=0.05, rule_matches=[rule_m])
    assert dec_rule.detection_source == "RULE"
    assert dec_rule.rf_probability == pytest.approx(0.05)  # RF PROBABILITY NEVER INFLATED!
    assert dec_rule.hybrid_risk_score == pytest.approx(0.85)  # Rule floor applied to hybrid risk score!
    assert dec_rule.severity == "HIGH"

    # Case 3: Concordant detection (prob 0.90, Rule HIGH)
    dec_concordant = hybrid.evaluate(rf_probability=0.90, rule_matches=[rule_m])
    assert dec_concordant.detection_source == "HYBRID"
    assert dec_concordant.rf_probability == pytest.approx(0.90)
    assert dec_concordant.hybrid_risk_score == pytest.approx(0.90)

    # Case 4: Neither (prob 0.02, no rules)
    dec_none = hybrid.evaluate(rf_probability=0.02, rule_matches=[])
    assert dec_none.detection_source == "NONE"
    assert dec_none.verdict == "BENIGN"
    assert dec_none.severity == "INFORMATIONAL"
