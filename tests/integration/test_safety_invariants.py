"""Integration tests for Deterministic Safety Gate non-bypassable invariants (Task 5 / Phase 2E).

Verifies the 4 inviolable safety invariants defined in SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 14:
1. Critical Infrastructure Exemption (Gateway, DNS, Identity cannot be isolated).
2. Mandatory Action Cooldown (No de-escalation to ALLOW within 30-step window).
3. Blast Radius Circuit Breaker (Max 5.0% simultaneously isolated endpoints).
4. Action Space Mode Clamp (3-action mode strictly forbids ISOLATE).
"""

from __future__ import annotations

import numpy as np
import pytest

from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.baselines import ResponsePolicy
from xrlids.response.safety import DEFAULT_CRITICAL_HOSTS, DeterministicSafetyGate
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode


class RogueAdversarialPolicy(ResponsePolicy):
    """Adversarial policy that tries to violate all safety rules by proposing ISOLATE everywhere."""

    name: str = "Rogue_Adversarial_Policy"

    def __init__(self, action_to_force: Action = Action.ISOLATE):
        self.action_to_force = action_to_force

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        return self.action_to_force

    def reset(self) -> None:
        pass


def test_critical_infrastructure_exemption():
    """Verify that critical hosts can NEVER be isolated under any circumstances."""
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)

    for crit_host in DEFAULT_CRITICAL_HOSTS:
        enforced, overridden, reason = gate.enforce_safety(
            step=1,
            flow_id="f1",
            host_id=crit_host,
            proposed_action=Action.ISOLATE,
        )
        assert enforced == Action.ALERT
        assert overridden is True
        assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"

    # Non-critical host should be allowed to isolate if not on cooldown
    enforced, overridden, reason = gate.enforce_safety(
        step=2,
        flow_id="f2",
        host_id="192.168.10.150",
        proposed_action=Action.ISOLATE,
    )
    assert enforced == Action.ISOLATE
    assert overridden is False


def test_mandatory_action_cooldown():
    """Verify that an endpoint under cooldown cannot oscillate back to ALLOW within 30 steps."""
    gate = DeterministicSafetyGate(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cooldown_steps=30,
        step_duration_s=1.0,
    )
    host = "192.168.10.99"

    # Step 10: Isolate host -> Cooldown set until step 40
    enforced, _, _ = gate.enforce_safety(10, "f1", host, Action.ISOLATE)
    assert enforced == Action.ISOLATE
    assert gate.get_remaining_cooldown(host, 10) == 30

    # Step 20 (< step 40): Policy tries to violently toggle back to ALLOW
    enforced, overridden, reason = gate.enforce_safety(20, "f2", host, Action.ALLOW)
    assert enforced == Action.ISOLATE
    assert overridden is True
    assert reason == "MANDATORY_ACTION_COOLDOWN"

    # Step 41 (> step 40): Cooldown expired, ALLOW now permitted
    enforced, overridden, reason = gate.enforce_safety(41, "f3", host, Action.ALLOW)
    assert enforced == Action.ALLOW
    assert overridden is False


def test_blast_radius_circuit_breaker():
    """Verify that isolation is capped at 5.0% of network population."""
    gate = DeterministicSafetyGate(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        blast_radius_threshold=0.05,
        min_hosts_for_circuit_breaker=20,
    )

    # Register 100 hosts
    for i in range(100):
        gate.enforce_safety(0, f"f_init_{i}", f"host_{i}", Action.ALLOW)

    # Isolate up to 5 hosts (5%)
    for i in range(5):
        enforced, _, _ = gate.enforce_safety(1, f"f_iso_{i}", f"host_{i}", Action.ISOLATE)
        assert enforced == Action.ISOLATE

    # The 6th host isolation must trip the circuit breaker (6% > 5%)
    enforced, overridden, reason = gate.enforce_safety(1, "f_iso_6", "host_6", Action.ISOLATE)
    assert enforced == Action.ALERT
    assert overridden is True
    assert reason == "BLAST_RADIUS_CIRCUIT_BREAKER"


def test_action_mode_3_action_clamp():
    """Verify that in 3-action mode, ISOLATE is strictly clamped to RATE_LIMIT."""
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.THREE_ACTION)
    host = "192.168.10.77"

    enforced, overridden, reason = gate.enforce_safety(1, "f1", host, Action.ISOLATE)
    assert enforced == Action.RATE_LIMIT
    assert overridden is True
    assert reason == "ACTION_MODE_3_ACTION_CLAMP"


def test_non_bypassable_safety_in_simulator():
    """Verify that even a rogue policy cannot bypass safety when run through OfflineResponseSimulator."""
    flows = [
        FlowRecord(
            flow_id=f"flow_{i}",
            host_id="192.168.10.1",  # ALL targeting Default Gateway!
            attack_score=0.99,
            true_label=1,
            flow_bytes_per_s=1000.0,
        )
        for i in range(25)
    ]

    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    rogue_policy = RogueAdversarialPolicy(action_to_force=Action.ISOLATE)

    sim = OfflineResponseSimulator(
        flows=flows,
        cost_engine=ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE),
        safety_gate=gate,
        state_builder=StateBuilder(),
        action_mode=ActionSpaceMode.FOUR_ACTION,
    )

    summary = sim.run_policy(rogue_policy, episode_id="adversarial_test")

    # Zero ISOLATE actions should have been enforced on the Default Gateway
    assert summary.action_counts.get("ISOLATE", 0) == 0
    assert summary.action_counts.get("ALERT", 0) == 25
    assert len(summary.override_counts) > 0
    assert summary.override_counts.get("CRITICAL_INFRASTRUCTURE_EXEMPTION", 0) == 25
