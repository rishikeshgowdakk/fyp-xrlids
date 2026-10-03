"""Unit tests for OfflineResponseSimulator and FlowRecord (Phase 2A Task 2)."""

import numpy as np
import pytest

from xrlids.response.baselines import (
    AlwaysAllowPolicy,
    HeuristicStateMachinePolicy,
    SingleThresholdPolicy,
    TwoTierThresholdPolicy,
)
from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.types import Action, ActionSpaceMode


def test_flow_record_initialization():
    """Verify FlowRecord creation with default and specified fields."""
    rec = FlowRecord(flow_id="f1", host_id="host-1", attack_score=0.85, true_label=1, flow_bytes_per_s=1200.0)
    assert rec.flow_id == "f1"
    assert rec.host_id == "host-1"
    assert rec.attack_score == 0.85
    assert rec.true_label == 1
    assert rec.flow_bytes_per_s == 1200.0


def test_simulator_reset_and_initial_state():
    """Verify reset clears state and returns causal 6D initial state vector."""
    flows = [
        FlowRecord(flow_id="f0", host_id="h0", attack_score=0.2, true_label=0, flow_bytes_per_s=500.0),
        FlowRecord(flow_id="f1", host_id="h1", attack_score=0.9, true_label=1, flow_bytes_per_s=1500.0),
    ]
    sim = OfflineResponseSimulator(flows=flows)
    init_state = sim.reset()

    assert isinstance(init_state, np.ndarray)
    assert init_state.shape == (6,)
    # Attack score should match first flow
    assert init_state[0] == pytest.approx(0.2)
    # Consecutive alerts initially 0
    assert init_state[2] == 0.0


def test_simulator_step_transition_and_consequences():
    """Verify single step simulation updates consequences and costs correctly."""
    flows = [
        FlowRecord(flow_id="f0", host_id="h0", attack_score=0.95, true_label=1),  # Uncontained attack if ALLOW
        FlowRecord(flow_id="f1", host_id="h0", attack_score=0.95, true_label=1),
    ]
    cost_engine = ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE)
    sim = OfflineResponseSimulator(flows=flows, cost_engine=cost_engine)
    sim.reset()

    # Step 0: Policy proposes ALLOW on attack flow
    next_state, reward, done, info = sim.step(Action.ALLOW)

    assert done is False
    assert info["flow_id"] == "f0"
    assert info["enforced_action"] == Action.ALLOW
    assert info["consequences"]["compromise_escalated"] is True
    # Base cost for uncontained attack under Standard Enterprise is 100.0
    assert info["total_cost"] == pytest.approx(100.0)
    assert reward == pytest.approx(-100.0)


def test_simulator_consecutive_alert_fatigue():
    """Verify consecutive alerts accumulate alert fatigue penalty across steps."""
    flows = [
        FlowRecord(flow_id=f"f{i}", host_id="h0", attack_score=0.6, true_label=0)
        for i in range(5)
    ]
    cost_engine = ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE, fatigue_threshold=2)
    sim = OfflineResponseSimulator(flows=flows, cost_engine=cost_engine)
    sim.reset()

    rewards = []
    for _ in range(5):
        _, r, _, info = sim.step(Action.ALERT)
        rewards.append(r)

    # Subsequent alerts should incur progressively worse reward due to fatigue penalty
    assert rewards[4] < rewards[0]


def test_simulator_run_policy_full_episode():
    """Verify run_policy executes full flow replay and produces valid EpisodeSummary."""
    flows = [
        FlowRecord(flow_id="f0", host_id="h0", attack_score=0.1, true_label=0),
        FlowRecord(flow_id="f1", host_id="h0", attack_score=0.2, true_label=0),
        FlowRecord(flow_id="f2", host_id="h1", attack_score=0.8, true_label=1),
        FlowRecord(flow_id="f3", host_id="h1", attack_score=0.9, true_label=1),
    ]
    sim = OfflineResponseSimulator(flows=flows)
    policy = SingleThresholdPolicy(threshold=0.50)

    summary = sim.run_policy(policy, episode_id="test_ep")

    assert summary.episode_id == "test_ep"
    assert summary.total_steps == 4
    assert len(summary.step_logs) == 4
    assert summary.action_counts[Action.ALLOW.name] == 2
    assert summary.action_counts[Action.ISOLATE.name] == 2
    assert summary.contained_attacks == 2
    assert summary.uncontained_attacks == 0


def test_simulator_three_action_clamp():
    """Verify 3-action mode clamps ISOLATE to RATE_LIMIT throughout simulation."""
    flows = [
        FlowRecord(flow_id="f0", host_id="h0", attack_score=0.9, true_label=1),
    ]
    sim = OfflineResponseSimulator(flows=flows, action_mode=ActionSpaceMode.THREE_ACTION)
    policy = SingleThresholdPolicy(threshold=0.50)  # Would choose ISOLATE in 4-action

    summary = sim.run_policy(policy)
    assert summary.action_counts[Action.ISOLATE.name] == 0
    assert summary.action_counts[Action.RATE_LIMIT.name] == 1
    assert "ACTION_MODE_3_ACTION_CLAMP" in summary.override_counts
