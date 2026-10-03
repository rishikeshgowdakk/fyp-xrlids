"""Response Policy Wrapper for Trained DQN Agents (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements ResponsePolicy interface for seamless integration with OfflineResponseSimulator.
Captures Q-values and decision margins at every step for Layer 2 Explainability auditing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np

from xrlids.response.baselines import ResponsePolicy
from xrlids.response.dqn.agent import DqnAgent
from xrlids.response.types import Action, ActionSpaceMode


@dataclass
class DqnPolicy(ResponsePolicy):
    """Evaluation policy executing deterministic action selection from a trained DQN agent."""

    agent: DqnAgent
    name: str = "DQN_Candidate_Policy"
    deterministic: bool = True

    # Audit telemetry recorded during execution
    last_q_values: np.ndarray | None = field(default=None, init=False)
    last_decision_margin: float | None = field(default=None, init=False)
    last_proposed_action: Action | None = field(default=None, init=False)
    q_value_history: list[dict[str, Any]] = field(default_factory=list, init=False)

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        """Select action via greedy Q-argmax and log decision margins."""
        epsilon = 0.0 if self.deterministic else 0.05
        action, q_vals, margin = self.agent.select_action(state, epsilon=epsilon)

        self.last_proposed_action = action
        self.last_q_values = q_vals
        self.last_decision_margin = margin

        action_q_map = {
            self.agent.action_space[i].name: float(q_vals[i])
            for i in range(len(self.agent.action_space))
        }

        self.q_value_history.append({
            "action": action.name,
            "q_values": action_q_map,
            "margin": margin,
        })
        return action

    def reset(self) -> None:
        """Reset step telemetry between evaluation episodes."""
        self.last_q_values = None
        self.last_decision_margin = None
        self.last_proposed_action = None
        self.q_value_history.clear()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.name,
            "action_mode": self.agent.action_mode.value,
            "input_dim": self.agent.input_dim,
            "deterministic": self.deterministic,
        }
