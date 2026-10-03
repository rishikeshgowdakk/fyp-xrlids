"""Unit tests verifying Phase 2 deterministic safety gate invariants (Task 5 & 12)."""

import pytest

from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.types import Action, ActionSpaceMode


def test_safety_gate_critical_infrastructure_exemption():
    """Verify that critical infrastructure hosts are never isolated and downgraded to ALERT."""
    gate = DeterministicSafetyGate(
        critical_hosts=frozenset(["192.168.10.1", "core-dns"]),
        action_mode=ActionSpaceMode.FOUR_ACTION,
    )

    # Attempt to isolate critical gateway host
    enforced, overridden, reason = gate.enforce_safety(
        step=0,
        flow_id="f1",
        host_id="192.168.10.1",
        proposed_action=Action.ISOLATE,
    )

    assert enforced == Action.ALERT
    assert overridden is True
    assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"

    # Non-critical host can be isolated
    enforced2, overridden2, _ = gate.enforce_safety(
        step=1,
        flow_id="f2",
        host_id="10.0.0.99",
        proposed_action=Action.ISOLATE,
    )
    assert enforced2 == Action.ISOLATE
    assert overridden2 is False


def test_safety_gate_3_action_clamp():
    """Verify that in 3-action mode, ISOLATE is clamped to RATE_LIMIT."""
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.THREE_ACTION)

    enforced, overridden, reason = gate.enforce_safety(
        step=0,
        flow_id="f1",
        host_id="10.0.0.5",
        proposed_action=Action.ISOLATE,
    )
    assert enforced == Action.RATE_LIMIT
    assert overridden is True
    assert reason == "ACTION_MODE_3_ACTION_CLAMP"


def test_safety_gate_mandatory_cooldown():
    """Verify mandatory cooldown prevents toggling from disruptive action to ALLOW within cooldown window."""
    default_gate = DeterministicSafetyGate(cooldown_steps=30, step_duration_s=1.0)
    assert default_gate.cooldown_seconds == 30.0

    gate = DeterministicSafetyGate(cooldown_steps=10, step_duration_s=1.0)
    assert gate.cooldown_seconds == 10.0

    # Step 0: Apply RATE_LIMIT on host-A
    enforced, _, _ = gate.enforce_safety(0, "f0", "host-A", Action.RATE_LIMIT)
    assert enforced == Action.RATE_LIMIT

    # Step 5: Policy tries to de-escalate to ALLOW while cooldown is active (expiry at 10)
    enforced2, overridden2, reason2 = gate.enforce_safety(5, "f1", "host-A", Action.ALLOW)
    assert enforced2 == Action.RATE_LIMIT
    assert overridden2 is True
    assert reason2 == "MANDATORY_ACTION_COOLDOWN"

    # Step 11: Cooldown has expired (step >= 10); policy de-escalates to ALLOW without override
    enforced3, overridden3, _ = gate.enforce_safety(11, "f2", "host-A", Action.ALLOW)
    assert enforced3 == Action.ALLOW
    assert overridden3 is False


def test_safety_gate_blast_radius_circuit_breaker():
    """Verify circuit breaker triggers when active isolated fraction exceeds 5%."""
    gate = DeterministicSafetyGate(
        blast_radius_threshold=0.05,
        min_hosts_for_circuit_breaker=20,
    )

    # Register 20 known hosts by running ALLOW on them
    for i in range(20):
        gate.enforce_safety(i, f"f_{i}", f"host_{i}", Action.ALLOW)

    # Isolate host_0: 1 / 20 = 0.05 (threshold is 0.05)
    enforced1, overridden1, _ = gate.enforce_safety(20, "f_iso1", "host_0", Action.ISOLATE)
    assert enforced1 == Action.ISOLATE
    assert overridden1 is False

    # Attempt to isolate host_1: projected 2 / 20 = 0.10 > 0.05 -> Circuit breaker triggers!
    enforced2, overridden2, reason2 = gate.enforce_safety(21, "f_iso2", "host_1", Action.ISOLATE)
    assert enforced2 == Action.ALERT
    assert overridden2 is True
    assert reason2 == "BLAST_RADIUS_CIRCUIT_BREAKER"


def test_safety_gate_override_logging():
    """Verify that every override is recorded in the override log with correct details."""
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.THREE_ACTION)
    gate.enforce_safety(0, "flow-99", "host-X", Action.ISOLATE)

    log = gate.override_log
    assert len(log) == 1
    assert log[0].flow_id == "flow-99"
    assert log[0].host_id == "host-X"
    assert log[0].proposed_action == Action.ISOLATE
    assert log[0].enforced_action == Action.RATE_LIMIT
    assert log[0].reason == "ACTION_MODE_3_ACTION_CLAMP"

    summary = gate.summary()
    assert summary["total_evaluations"] == 1
    assert summary["total_overrides"] == 1
    assert summary["reasons"]["ACTION_MODE_3_ACTION_CLAMP"] == 1
