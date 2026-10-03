"""DQN Training Engine with PER and Validation Checkpoint Selection (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.2 & 9.3:
- Episode slicing (T_ep = 100 flows) across ordered flow stream from D_pol_train
- Terminal condition: T_ep steps or confirmed attack isolation
- Strict separation: D_pol_test is never seen or touched during training
- Periodic validation on D_pol_val with CheckpointManager tracking
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time
from typing import Any, Sequence
import numpy as np

from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.dqn.agent import DqnAgent
from xrlids.response.dqn.checkpointing import CheckpointManager
from xrlids.response.dqn.policy import DqnPolicy
from xrlids.response.dqn.replay import PrioritizedReplayBuffer
from xrlids.response.dqn.schedule import BetaSchedule, EpsilonSchedule
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode, EpisodeSummary


@dataclass
class TrainingConfig:
    """Hyperparameter specification for Phase 2B DQN training."""

    total_steps: int = 50_000
    batch_size: int = 64
    warmup_steps: int = 500
    eval_interval_steps: int = 5_000
    max_episode_steps: int = 100
    early_termination_on_isolated_attack: bool = True

    # Schedules
    epsilon_start: float = 1.0
    epsilon_min: float = 0.05
    epsilon_decay_steps: int = 50_000
    beta_start: float = 0.4
    beta_end: float = 1.0

    # Optimization
    learning_rate: float = 1e-3
    gamma: float = 0.95
    tau_target: float = 0.005
    replay_capacity: int = 100_000
    per_alpha: float = 0.6

    # Environment
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    cost_regime: CostRegime = CostRegime.STANDARD_ENTERPRISE
    random_seed: int = 42


class DqnTrainer:
    """Orchestrates DQN policy training on D_pol_train and validation tracking on D_pol_val."""

    def __init__(
        self,
        agent: DqnAgent,
        train_flows: list[FlowRecord],
        val_flows: list[FlowRecord],
        config: TrainingConfig,
        checkpoint_dir: str | Path,
    ) -> None:
        self.agent = agent
        self.train_flows = train_flows
        self.val_flows = val_flows
        self.config = config
        self.checkpoint_dir = Path(checkpoint_dir)

        self.replay_buffer = PrioritizedReplayBuffer(
            capacity=config.replay_capacity,
            alpha=config.per_alpha,
        )
        self.eps_schedule = EpsilonSchedule(
            start_epsilon=config.epsilon_start,
            min_epsilon=config.epsilon_min,
            decay_steps=config.epsilon_decay_steps,
        )
        self.beta_schedule = BetaSchedule(
            start_beta=config.beta_start,
            end_beta=config.beta_end,
            total_steps=config.total_steps,
        )
        self.checkpoint_manager = CheckpointManager(
            checkpoint_dir=self.checkpoint_dir,
            selection_metric="mean_cost_per_flow",
            maximize=False,
        )

        self.training_history: list[dict[str, Any]] = []

    def train(self) -> dict[str, Any]:
        """Execute full training loop over designated policy training flows."""
        cost_engine = ResearchCostEngine(regime=self.config.cost_regime)
        flow_idx = 0
        n_train_flows = len(self.train_flows)

        step = 0
        episode_count = 0
        t0 = time.time()

        while step < self.config.total_steps:
            # 1. Initialize episode
            safety_gate = DeterministicSafetyGate(action_mode=self.config.action_mode)
            state_builder = StateBuilder()

            # Slice episode flows
            ep_flows = []
            for _ in range(self.config.max_episode_steps):
                ep_flows.append(self.train_flows[flow_idx % n_train_flows])
                flow_idx += 1

            sim = OfflineResponseSimulator(
                flows=ep_flows,
                cost_engine=cost_engine,
                safety_gate=safety_gate,
                state_builder=state_builder,
                action_mode=self.config.action_mode,
                random_seed=self.config.random_seed + episode_count,
            )

            state = sim.reset()
            episode_count += 1
            ep_step = 0

            while ep_step < len(ep_flows) and step < self.config.total_steps:
                epsilon = self.eps_schedule.get_value(step)
                beta = self.beta_schedule.get_value(step)

                # Select action with epsilon-greedy policy
                proposed_action, _, _ = self.agent.select_action(state, epsilon=epsilon)
                action_idx = self.agent.action_to_index(proposed_action)

                # Step simulation
                next_state, reward, done_sim, info = sim.step(proposed_action)
                ep_step += 1
                step += 1

                # Check terminal condition
                flow = ep_flows[ep_step - 1]
                done = done_sim
                if self.config.early_termination_on_isolated_attack:
                    if info["enforced_action"] == Action.ISOLATE and flow.true_label == 1:
                        done = True

                # Store in PER buffer
                self.replay_buffer.push(
                    state=state,
                    action=action_idx,
                    reward=reward,
                    next_state=next_state,
                    done=done,
                )
                state = next_state

                # Optimize network
                loss_val = None
                if len(self.replay_buffer) >= self.config.warmup_steps:
                    batch, tree_indices, weights = self.replay_buffer.sample(
                        batch_size=self.config.batch_size,
                        beta=beta,
                    )
                    loss_val, td_errors = self.agent.train_step(batch, weights)
                    self.replay_buffer.update_priorities(tree_indices, td_errors)

                # Evaluation check
                if step % self.config.eval_interval_steps == 0 or step == self.config.total_steps:
                    val_metrics = self.evaluate_validation()
                    is_best, cp_path = self.checkpoint_manager.register_evaluation(
                        step=step,
                        metrics=val_metrics,
                        online_net=self.agent.online_net,
                        target_net=self.agent.target_net,
                        optimizer=self.agent.optimizer,
                        config={"step": step, "epsilon": epsilon, "loss": loss_val},
                    )
                    self.training_history.append({
                        "step": step,
                        "epsilon": float(epsilon),
                        "beta": float(beta),
                        "loss": float(loss_val) if loss_val is not None else None,
                        "val_metrics": val_metrics,
                        "is_best": is_best,
                        "checkpoint": str(cp_path),
                    })

                if done:
                    break

        elapsed = time.time() - t0
        return {
            "total_steps": step,
            "episodes_completed": episode_count,
            "training_time_seconds": elapsed,
            "checkpoint_summary": self.checkpoint_manager.to_dict(),
            "history": self.training_history,
        }

    def evaluate_validation(self, sample_limit: int | None = None) -> dict[str, Any]:
        """Evaluate current policy deterministically on validation flows (D_pol_val)."""
        eval_flows = self.val_flows
        if sample_limit and sample_limit < len(eval_flows):
            eval_flows = eval_flows[:sample_limit]

        cost_engine = ResearchCostEngine(regime=self.config.cost_regime)
        safety_gate = DeterministicSafetyGate(action_mode=self.config.action_mode)
        state_builder = StateBuilder()

        sim = OfflineResponseSimulator(
            flows=eval_flows,
            cost_engine=cost_engine,
            safety_gate=safety_gate,
            state_builder=state_builder,
            action_mode=self.config.action_mode,
            random_seed=self.config.random_seed,
        )

        policy = DqnPolicy(agent=self.agent, deterministic=True)
        summary: EpisodeSummary = sim.run_policy(policy, episode_id="validation_eval")

        return {
            "total_steps": summary.total_steps,
            "total_cost": summary.total_cost,
            "mean_cost_per_flow": summary.mean_cost,
            "false_quarantine_rate": summary.false_quarantine_rate,
            "business_availability_score_pct": summary.business_availability_score,
            "action_chattering_index": summary.action_chattering_index,
            "mitigation_delay_steps": summary.mitigation_delay,
            "action_counts": summary.action_counts,
            "override_counts": summary.override_counts,
            "contained_attacks": summary.contained_attacks,
            "uncontained_attacks": summary.uncontained_attacks,
        }
