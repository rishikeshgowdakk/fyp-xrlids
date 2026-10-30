"""Unit tests verifying decision consistency between deterministic rules, DQN state, and safety gate."""

import numpy as np
import pytest
import torch

from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.safety import Action, ActionSpaceMode, DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.rules.engine import RuleEngine, RuleMatch
from xrlids.rules.hybrid import HybridDecisionEngine


def test_high_severity_rule_elevates_threat_score_and_dqn_state():
    """Verify that a CRITICAL/HIGH deterministic rule elevates threat score above RF threshold."""
    hybrid_engine = HybridDecisionEngine()
    state_builder = StateBuilder()

    # Case: RF says 0.0000 (benign), but deterministic rule detects extreme SYN flood
    rf_score = 0.0000
    rule_matches = [
        RuleMatch(
            rule_id="RULE-SYN-FLOOD",
            name="SYN Flood Invariant",
            severity="HIGH",
            description="Extreme SYN flag asymmetry without ACK response",
            matched_value="syn=95, ack=0",
        )
    ]

    hybrid_dec = hybrid_engine.evaluate(rf_probability=rf_score, rule_matches=rule_matches)

    assert hybrid_dec.is_attack is True
    assert hybrid_dec.verdict == "ATTACK"
    assert hybrid_dec.detection_source == "RULE"
    assert hybrid_dec.threat_score >= 0.85, "Rule floor must guarantee threat_score >= 0.85"

    # Verify state builder receives arbitrated score
    state_vec = state_builder.build_state(
        attack_score=hybrid_dec.threat_score,
        flow_bytes_per_s=150000.0,
    )
    assert state_vec[0] >= 0.85, f"Expected S_t >= 0.85, got {state_vec[0]}"


def test_critical_host_safety_override():
    """Verify that the Deterministic Safety Gate overrides an aggressive ISOLATE on critical hosts."""
    safety_gate = DeterministicSafetyGate(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        critical_hosts=frozenset({"192.168.1.1", "10.0.0.1", "8.8.8.8"}),
    )

    enforced_act, overridden, reason = safety_gate.enforce_safety(
        step=1,
        flow_id="test-flow-crit",
        host_id="192.168.1.1",
        proposed_action=Action.ISOLATE,
    )

    assert overridden is True
    assert enforced_act != Action.ISOLATE
    assert enforced_act in (Action.RATE_LIMIT, Action.ALERT)
    assert "critical" in reason.lower()


def test_blast_radius_safety_override():
    """Verify that the blast-radius circuit breaker blocks excessive simultaneous isolations."""
    safety_gate = DeterministicSafetyGate(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        blast_radius_threshold=0.05,
        min_hosts_for_circuit_breaker=20,
    )

    # First isolation on host 1 is approved (1 / 20 = 5% <= 5%)
    enforced1, ov1, _ = safety_gate.enforce_safety(step=1, flow_id="f1", host_id="10.0.0.51", proposed_action=Action.ISOLATE)
    assert enforced1 == Action.ISOLATE
    assert ov1 is False

    # Second isolation on host 2 exceeds blast radius threshold (2 / 20 = 10% > 5%)
    enforced2, ov2, reason2 = safety_gate.enforce_safety(
        step=2,
        flow_id="f2",
        host_id="10.0.0.52",
        proposed_action=Action.ISOLATE,
    )
    assert ov2 is True
    assert enforced2 != Action.ISOLATE
    assert "blast_radius" in reason2.lower()
