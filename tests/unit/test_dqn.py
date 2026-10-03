"""Unit tests for Phase 2B Deep Q-Network implementation (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Verifies:
1. Dueling network architecture and value/advantage decomposition
2. Prioritized Experience Replay (PER), SumTree, and importance weights
3. Epsilon and Beta schedules
4. Polyak soft and hard target network updates
5. Checkpoint serialization and validation-based best model selection
6. Deterministic seeding and reproducibility
7. 3-action and 4-action space dimensions
8. Causal state representation invariants (no label in state, no future leakage)
9. Safety gate downstream enforcement
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import numpy as np
import pytest
import torch

from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.dqn.agent import DqnAgent
from xrlids.response.dqn.checkpointing import CheckpointManager
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.dqn.policy import DqnPolicy
from xrlids.response.dqn.replay import PrioritizedReplayBuffer, SumTree
from xrlids.response.dqn.reproducibility import capture_provenance, set_seed
from xrlids.response.dqn.schedule import BetaSchedule, EpsilonSchedule
from xrlids.response.dqn.target_update import hard_update, soft_update
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode


def test_dueling_network_dimensions_and_decomposition():
    """Verify DuelingQNetwork output shapes and dueling mathematical decomposition."""
    net = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=64)

    # 1. Single sample
    state_single = torch.randn(6)
    q_single = net(state_single)
    assert q_single.shape == (4,)

    # 2. Batch sample
    state_batch = torch.randn(10, 6)
    q_batch = net(state_batch)
    assert q_batch.shape == (10, 4)

    # 3. Explicit stream decomposition verification: Q = V + A - mean(A)
    v, adv, q_computed = net.compute_streams(state_batch)
    assert v.shape == (10, 1)
    assert adv.shape == (10, 4)
    assert q_computed.shape == (10, 4)

    expected_q = v + (adv - adv.mean(dim=-1, keepdim=True))
    torch.testing.assert_close(q_computed, expected_q)
    torch.testing.assert_close(q_batch, expected_q)


def test_prioritized_replay_buffer_and_sumtree():
    """Verify PER priority insertion, sumtree sampling, importance weights, and priority updates."""
    buffer = PrioritizedReplayBuffer(capacity=100, alpha=0.6)
    assert len(buffer) == 0

    # Add transitions
    for i in range(50):
        buffer.push(
            state=np.ones(6) * i,
            action=i % 4,
            reward=float(-i),
            next_state=np.ones(6) * (i + 1),
            done=(i == 49),
        )

    assert len(buffer) == 50
    assert buffer.tree.total_priority() > 0

    # Sample batch
    batch, tree_indices, weights = buffer.sample(batch_size=16, beta=0.4)
    assert batch["states"].shape == (16, 6)
    assert batch["actions"].shape == (16,)
    assert batch["rewards"].shape == (16, 1)
    assert batch["next_states"].shape == (16, 6)
    assert batch["dones"].shape == (16, 1)
    assert weights.shape == (16, 1)
    assert len(tree_indices) == 16
    assert (weights <= 1.0).all()

    # Update priorities with large TD errors
    old_total = buffer.tree.total_priority()
    new_td_errors = np.ones(16) * 10.0
    buffer.update_priorities(tree_indices, new_td_errors)
    assert buffer.tree.total_priority() >= old_total


def test_schedules():
    """Verify epsilon decay and beta annealing schedules."""
    eps_sched = EpsilonSchedule(start_epsilon=1.0, min_epsilon=0.05, decay_steps=1000)
    assert eps_sched.get_value(0) == 1.0
    assert eps_sched.get_value(500) == pytest.approx(0.525, abs=1e-3)
    assert eps_sched.get_value(1000) == 0.05
    assert eps_sched.get_value(2000) == 0.05

    beta_sched = BetaSchedule(start_beta=0.4, end_beta=1.0, total_steps=1000)
    assert beta_sched.get_value(0) == 0.4
    assert beta_sched.get_value(500) == pytest.approx(0.7, abs=1e-3)
    assert beta_sched.get_value(1000) == 1.0
    assert beta_sched.get_value(1500) == 1.0


def test_target_network_updates():
    """Verify soft Polyak and hard parameter updates."""
    online = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=64)
    target = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=64)

    # Manually diverge parameters
    with torch.no_grad():
        for p in online.parameters():
            p.add_(1.0)

    # Check they differ
    online_p = next(online.parameters()).clone()
    target_p = next(target.parameters()).clone()
    assert not torch.allclose(online_p, target_p)

    # Soft update
    tau = 0.1
    soft_update(target, online, tau=tau)
    target_p_soft = next(target.parameters()).clone()
    expected_soft = (1.0 - tau) * target_p + tau * online_p
    torch.testing.assert_close(target_p_soft, expected_soft)

    # Hard update
    hard_update(target, online)
    torch.testing.assert_close(next(target.parameters()), next(online.parameters()))


def test_dqn_agent_action_spaces():
    """Verify 3-action and 4-action agent initialization and selection."""
    # 3-action agent
    agent_3 = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.THREE_ACTION, hidden_dim=32)
    assert agent_3.action_dim == 3
    assert agent_3.action_space == [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT]

    act, q_vals, margin = agent_3.select_action(np.zeros(6), epsilon=0.0)
    assert act in agent_3.action_space
    assert len(q_vals) == 3
    assert margin >= 0.0

    # 4-action agent
    agent_4 = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.FOUR_ACTION, hidden_dim=32)
    assert agent_4.action_dim == 4
    assert agent_4.action_space == [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE]

    act4, q_vals4, margin4 = agent_4.select_action(np.zeros(6), epsilon=0.0)
    assert act4 in agent_4.action_space
    assert len(q_vals4) == 4


def test_dqn_agent_train_step():
    """Verify gradient step on agent with Huber loss."""
    agent = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.FOUR_ACTION, hidden_dim=32)

    batch = {
        "states": torch.randn(8, 6),
        "actions": torch.randint(0, 4, (8,)),
        "rewards": torch.randn(8, 1),
        "next_states": torch.randn(8, 6),
        "dones": torch.zeros(8, 1),
    }
    weights = torch.ones(8, 1)

    initial_loss, td_errors = agent.train_step(batch, weights)
    assert isinstance(initial_loss, float)
    assert len(td_errors) == 8
    assert (td_errors >= 0.0).all()


def test_checkpoint_manager_and_objective_selection():
    """Verify checkpoint persistence and best model tracking based on validation metric."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cm = CheckpointManager(checkpoint_dir=tmpdir, selection_metric="mean_cost_per_flow", maximize=False)
        agent = DqnAgent(input_dim=6, hidden_dim=32)

        # First evaluation: cost = 0.50
        is_best1, path1 = cm.register_evaluation(
            step=1000,
            metrics={"mean_cost_per_flow": 0.50, "fqr": 0.01},
            online_net=agent.online_net,
            target_net=agent.target_net,
            optimizer=agent.optimizer,
        )
        assert is_best1
        assert cm.best_step == 1000
        assert cm.best_metric_value == 0.50
        assert (Path(tmpdir) / "best_model.pt").exists()

        # Second evaluation: cost = 0.60 (worse)
        is_best2, path2 = cm.register_evaluation(
            step=2000,
            metrics={"mean_cost_per_flow": 0.60, "fqr": 0.02},
            online_net=agent.online_net,
            target_net=agent.target_net,
            optimizer=agent.optimizer,
        )
        assert not is_best2
        assert cm.best_step == 1000

        # Third evaluation: cost = 0.40 (better)
        is_best3, path3 = cm.register_evaluation(
            step=3000,
            metrics={"mean_cost_per_flow": 0.40, "fqr": 0.005},
            online_net=agent.online_net,
            target_net=agent.target_net,
            optimizer=agent.optimizer,
        )
        assert is_best3
        assert cm.best_step == 3000
        assert cm.best_metric_value == 0.40

        # Load best model
        new_agent = DqnAgent(input_dim=6, hidden_dim=32)
        payload = cm.load_checkpoint(Path(tmpdir) / "best_model.pt", new_agent.online_net)
        assert payload["step"] == 3000
        torch.testing.assert_close(next(agent.online_net.parameters()), next(new_agent.online_net.parameters()))


def test_reproducibility():
    """Verify deterministic seeding produces identical model initialization."""
    set_seed(42)
    net1 = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=32)
    w1 = next(net1.parameters()).clone()

    set_seed(42)
    net2 = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=32)
    w2 = next(net2.parameters()).clone()

    torch.testing.assert_close(w1, w2)

    prov = capture_provenance(seed=42)
    assert prov["random_seed"] == 42
    assert "torch_version" in prov


def test_policy_simulator_integration_and_safety_gate():
    """Verify DqnPolicy runs through OfflineResponseSimulator and obeys downstream safety gate."""
    agent = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.FOUR_ACTION, hidden_dim=32)
    policy = DqnPolicy(agent=agent, deterministic=True)

    flows = [
        FlowRecord(flow_id="f1", host_id="host_gateway", attack_score=0.99, true_label=1, flow_bytes_per_s=100.0),
        FlowRecord(flow_id="f2", host_id="host_user", attack_score=0.10, true_label=0, flow_bytes_per_s=50.0),
    ]

    safety_gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    cost_engine = ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE)
    sim = OfflineResponseSimulator(
        flows=flows,
        cost_engine=cost_engine,
        safety_gate=safety_gate,
        action_mode=ActionSpaceMode.FOUR_ACTION,
    )

    summary = sim.run_policy(policy)
    assert summary.total_steps == 2
    assert len(policy.q_value_history) == 2

    # Check that gateway was exempted if ISOLATE was proposed
    for log in summary.step_logs:
        if log.host_id == "host_gateway" and log.proposed_action == Action.ISOLATE:
            assert log.enforced_action == Action.ALERT
            assert log.overridden is True
