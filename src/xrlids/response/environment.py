"""Offline Response Simulation Environment for Phase 2 (Task 2).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 6:
    Offline Replay Simulator with non-bypassable Safety Gate and
    simulated transition / consequence engine.

Strict Boundaries:
- ZERO network mutations (no iptables, nftables, tc, socket drops, eBPF).
- Operates entirely offline against ordered flow data.
- Enforces causal state observations without future information or label leakage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence
import numpy as np
import pandas as pd

from xrlids.response.baselines import ResponsePolicy
from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.metrics import evaluate_response_run
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode, EpisodeSummary, StepLog


@dataclass
class FlowRecord:
    """Standardized representation of a single ordered network flow for offline replay."""

    flow_id: str | int
    host_id: str
    attack_score: float  # S_t in [0.0, 1.0] from frozen Phase 1 detector
    true_label: int      # 0: benign, 1: attack (for consequence/cost evaluation ONLY)
    flow_bytes_per_s: float = 0.0


@dataclass
class OfflineResponseSimulator:
    """Offline flow replay environment simulating autonomous responses and consequence dynamics."""

    flows: list[FlowRecord]
    cost_engine: ResearchCostEngine = field(default_factory=ResearchCostEngine)
    safety_gate: DeterministicSafetyGate = field(default_factory=DeterministicSafetyGate)
    state_builder: StateBuilder = field(default_factory=StateBuilder)
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    random_seed: int = 42

    # Internal simulation state
    _current_step: int = field(default=0, init=False)
    _consecutive_alerts: int = field(default=0, init=False)
    _host_compromise_state: dict[str, int] = field(default_factory=dict, init=False)
    _step_logs: list[StepLog] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.safety_gate.action_mode = self.action_mode
        self.reset()

    def reset(self) -> np.ndarray:
        """Reset simulator, state builder, and safety gate to initial clean state."""
        self._current_step = 0
        self._consecutive_alerts = 0
        self._host_compromise_state.clear()
        self._step_logs.clear()
        self.safety_gate.reset()
        self.state_builder.reset()

        if not self.flows:
            return np.zeros(6, dtype=np.float32)

        first_flow = self.flows[0]
        initial_state = self.state_builder.build_state(
            attack_score=first_flow.attack_score,
            flow_bytes_per_s=first_flow.flow_bytes_per_s,
            cooldown_remaining=0,
            last_action=Action.ALLOW,
        )
        return initial_state

    def step(
        self,
        proposed_action: Action,
    ) -> tuple[np.ndarray, float, bool, dict[str, Any]]:
        """Advance the simulation environment by one flow step.

        Parameters
        ----------
        proposed_action: Action
            Action recommended by the upstream policy.

        Returns
        -------
        tuple[np.ndarray, float, bool, dict[str, Any]]
            (next_state, reward, done, step_info)
        """
        if self._current_step >= len(self.flows):
            raise IndexError("Simulation already concluded. Call reset() before stepping again.")

        flow = self.flows[self._current_step]
        step_idx = self._current_step

        # 1. Enforce deterministic safety invariants
        enforced_action, overridden, override_reason = self.safety_gate.enforce_safety(
            step=step_idx,
            flow_id=flow.flow_id,
            host_id=flow.host_id,
            proposed_action=proposed_action,
        )

        # 2. Update consecutive alert tracker for alert fatigue calculation
        if enforced_action == Action.ALERT:
            self._consecutive_alerts += 1
        else:
            self._consecutive_alerts = 0

        # 3. Simulated Consequence Engine (Modeling Assumptions)
        # Check active cooldown on this host
        in_cooldown = (self.safety_gate.get_remaining_cooldown(flow.host_id, step_idx) > 0)
        prev_action = self.state_builder._last_action

        # Simulated transition dynamics:
        consequences: dict[str, Any] = {
            "flow_delivered": True,
            "bandwidth_fraction": 1.0,
            "compromise_escalated": False,
        }

        if enforced_action == Action.ALLOW:
            if flow.true_label == 1:
                # Attack allowed: increment host compromise counter (simulated assumption)
                self._host_compromise_state[flow.host_id] = self._host_compromise_state.get(flow.host_id, 0) + 1
                consequences["compromise_escalated"] = True
        elif enforced_action == Action.ALERT:
            # Audit logged; traffic delivered
            if flow.true_label == 1:
                self._host_compromise_state[flow.host_id] = self._host_compromise_state.get(flow.host_id, 0) + 1
                consequences["compromise_escalated"] = True
        elif enforced_action == Action.RATE_LIMIT:
            # Simulated 90% throughput reduction
            consequences["bandwidth_fraction"] = 0.10
            if flow.true_label == 1:
                # Attack throttled: compromise does not escalate
                consequences["attack_throttled"] = True
        elif enforced_action == Action.ISOLATE:
            # Simulated total drop & RST
            consequences["flow_delivered"] = False
            consequences["bandwidth_fraction"] = 0.0
            if flow.true_label == 1:
                consequences["attack_contained"] = True
            else:
                consequences["false_outage"] = True

        # 4. Evaluate Cost & Step Reward
        base_cost, chatter_cost, fatigue_cost, total_cost, reward = self.cost_engine.evaluate_step(
            action=enforced_action,
            y_true=flow.true_label,
            prev_action=prev_action,
            in_cooldown=in_cooldown,
            consecutive_alerts=self._consecutive_alerts,
        )

        # Current state before updating history
        current_state = self.state_builder.build_state(
            attack_score=flow.attack_score,
            flow_bytes_per_s=flow.flow_bytes_per_s,
            cooldown_remaining=self.safety_gate.get_remaining_cooldown(flow.host_id, step_idx),
            last_action=prev_action,
        )

        # Record step log
        log_entry = StepLog(
            step=step_idx,
            flow_id=flow.flow_id,
            host_id=flow.host_id,
            true_label=flow.true_label,
            attack_score=flow.attack_score,
            state=current_state,
            proposed_action=proposed_action,
            enforced_action=enforced_action,
            overridden=overridden,
            override_reason=override_reason,
            base_cost=base_cost,
            chattering_penalty=chatter_cost,
            fatigue_penalty=fatigue_cost,
            total_cost=total_cost,
            reward=reward,
            consequences=consequences,
        )
        self._step_logs.append(log_entry)

        # 5. Advance State Builder History
        self.state_builder.update_history(
            attack_score=flow.attack_score,
            enforced_action=enforced_action,
            cooldown_remaining=self.safety_gate.get_remaining_cooldown(flow.host_id, step_idx),
        )

        # 6. Advance step and construct next observation
        self._current_step += 1
        done = (self._current_step >= len(self.flows))

        if not done:
            next_flow = self.flows[self._current_step]
            next_cool = self.safety_gate.get_remaining_cooldown(next_flow.host_id, self._current_step)
            next_state = self.state_builder.build_state(
                attack_score=next_flow.attack_score,
                flow_bytes_per_s=next_flow.flow_bytes_per_s,
                cooldown_remaining=next_cool,
                last_action=enforced_action,
            )
        else:
            next_state = np.zeros(6, dtype=np.float32)

        info = {
            "step": step_idx,
            "flow_id": flow.flow_id,
            "host_id": flow.host_id,
            "enforced_action": enforced_action,
            "overridden": overridden,
            "override_reason": override_reason,
            "total_cost": total_cost,
            "consequences": consequences,
        }

        return next_state, reward, done, info

    def run_policy(
        self,
        policy: ResponsePolicy,
        *,
        episode_id: str = "offline_replay",
    ) -> EpisodeSummary:
        """Execute a complete replay run for the given policy from step 0 to completion."""
        state = self.reset()
        policy.reset()

        while self._current_step < len(self.flows):
            flow = self.flows[self._current_step]
            # Policy proposes action conditioned strictly on state and current score
            proposed = policy.predict_action(
                state=state,
                attack_score=flow.attack_score,
                host_id=flow.host_id,
            )
            state, reward, done, _ = self.step(proposed)
            if done:
                break

        # Compute summary metrics across all steps
        actions = [log.enforced_action for log in self._step_logs]
        y_true = [log.true_label for log in self._step_logs]
        costs = [log.total_cost for log in self._step_logs]
        metrics = evaluate_response_run(actions, y_true, costs)

        action_counts = {
            Action.ALLOW.name: sum(1 for a in actions if a == Action.ALLOW),
            Action.ALERT.name: sum(1 for a in actions if a == Action.ALERT),
            Action.RATE_LIMIT.name: sum(1 for a in actions if a == Action.RATE_LIMIT),
            Action.ISOLATE.name: sum(1 for a in actions if a == Action.ISOLATE),
        }

        override_counts: dict[str, int] = {}
        for log in self._step_logs:
            if log.overridden and log.override_reason:
                override_counts[log.override_reason] = override_counts.get(log.override_reason, 0) + 1

        uncontained = sum(1 for log in self._step_logs if log.true_label == 1 and log.enforced_action in (Action.ALLOW, Action.ALERT))
        contained = sum(1 for log in self._step_logs if log.true_label == 1 and log.enforced_action in (Action.RATE_LIMIT, Action.ISOLATE))

        summary = EpisodeSummary(
            episode_id=episode_id,
            total_steps=len(self._step_logs),
            total_cost=float(np.sum(costs)),
            mean_cost=float(np.mean(costs)) if costs else 0.0,
            total_reward=float(sum(log.reward for log in self._step_logs)),
            action_counts=action_counts,
            override_counts=override_counts,
            false_quarantine_rate=metrics["false_quarantine_rate"],
            business_availability_score=metrics["business_availability_score_pct"],
            action_chattering_index=metrics["action_chattering_index"],
            mitigation_delay=metrics["mitigation_delay_steps"],
            uncontained_attacks=uncontained,
            contained_attacks=contained,
            step_logs=list(self._step_logs),
        )
        return summary
