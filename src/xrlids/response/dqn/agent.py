"""DQN Agent with Dueling Architecture and Huber Loss (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.1 & 9.2:
- Action space support: 3-action (ALLOW, ALERT, RATE_LIMIT) and 4-action (+ ISOLATE)
- Huber / Smooth L1 loss
- Polyak soft target network update (tau = 0.005)
- Discount factor gamma = 0.95
- Epsilon-greedy action selection with Q-margin calculation
"""

from __future__ import annotations

from typing import Sequence
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.dqn.target_update import hard_update, soft_update
from xrlids.response.types import Action, ActionSpaceMode


class DqnAgent:
    """Deep Q-Learning agent managing dueling networks, action selection, and optimization."""

    def __init__(
        self,
        input_dim: int = 6,
        action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION,
        hidden_dim: int = 64,
        learning_rate: float = 1e-3,
        gamma: float = 0.95,
        tau_target: float = 0.005,
        device: str | torch.device = "cpu",
    ) -> None:
        self.input_dim = input_dim
        self.action_mode = action_mode
        self.gamma = gamma
        self.tau_target = tau_target
        self.device = torch.device(device)

        if action_mode == ActionSpaceMode.THREE_ACTION:
            self.action_space: list[Action] = [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT]
        else:
            self.action_space: list[Action] = [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE]

        self.action_dim = len(self.action_space)

        self.online_net = DuelingQNetwork(
            input_dim=input_dim,
            action_dim=self.action_dim,
            hidden_dim=hidden_dim,
        ).to(self.device)

        self.target_net = DuelingQNetwork(
            input_dim=input_dim,
            action_dim=self.action_dim,
            hidden_dim=hidden_dim,
        ).to(self.device)

        hard_update(self.target_net, self.online_net)
        self.target_net.eval()

        self.optimizer = optim.Adam(self.online_net.parameters(), lr=learning_rate)
        self.loss_fn = nn.SmoothL1Loss(reduction="none")

    def select_action(
        self,
        state: np.ndarray,
        epsilon: float = 0.0,
    ) -> tuple[Action, np.ndarray, float]:
        """Select an action using epsilon-greedy policy and return Q-values and decision margin.

        Returns
        -------
        action : Action
            Selected Action enum.
        q_values : np.ndarray
            Array of Q-values for each action in the action space.
        margin : float
            Difference between top Q-value and second-highest Q-value.
        """
        state_t = torch.as_tensor(state, dtype=torch.float32, device=self.device)
        self.online_net.eval()
        with torch.no_grad():
            q_vals = self.online_net(state_t).cpu().numpy().flatten()

        sorted_q = np.sort(q_vals)[::-1]
        margin = float(sorted_q[0] - sorted_q[1]) if len(sorted_q) > 1 else float(sorted_q[0])

        if np.random.rand() < epsilon:
            action_idx = int(np.random.randint(0, self.action_dim))
        else:
            action_idx = int(np.argmax(q_vals))

        selected_action = self.action_space[action_idx]
        return selected_action, q_vals, margin

    def train_step(
        self,
        batch: dict[str, torch.Tensor],
        weights: torch.Tensor,
    ) -> tuple[float, np.ndarray]:
        """Execute a single prioritized gradient descent step using Bellman error.

        Parameters
        ----------
        batch : dict[str, torch.Tensor]
            Dictionary containing 'states', 'actions', 'rewards', 'next_states', 'dones'.
        weights : torch.Tensor
            Importance sampling weights of shape (batch_size, 1).

        Returns
        -------
        loss_val : float
            Weighted Smooth L1 loss value.
        td_errors : np.ndarray
            Absolute TD errors for PER priority updating.
        """
        self.online_net.train()

        states = batch["states"].to(self.device)
        actions = batch["actions"].to(self.device)
        rewards = batch["rewards"].to(self.device)
        next_states = batch["next_states"].to(self.device)
        dones = batch["dones"].to(self.device)
        weights = weights.to(self.device)

        # Current Q estimates: Q(s, a)
        q_preds = self.online_net(states).gather(1, actions.unsqueeze(1))

        # Target Q calculation with frozen target net: r + gamma * max_{a'} Q_target(s', a') * (1 - done)
        with torch.no_grad():
            q_next = self.target_net(next_states)
            max_q_next = q_next.max(dim=1, keepdim=True)[0]
            target_q = rewards + (1.0 - dones) * self.gamma * max_q_next

        # Elementwise Huber loss
        elementwise_loss = self.loss_fn(q_preds, target_q)
        loss = (elementwise_loss * weights).mean()

        self.optimizer.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(self.online_net.parameters(), max_norm=10.0)
        self.optimizer.step()

        # Polyak soft target network update
        soft_update(self.target_net, self.online_net, tau=self.tau_target)

        # TD errors for PER priority update: |Q(s, a) - target_q|
        td_errors = torch.abs(q_preds - target_q).detach().cpu().numpy().flatten()
        return float(loss.item()), td_errors

    def action_to_index(self, action: Action) -> int:
        """Map Action enum to network output index."""
        return self.action_space.index(action)

    def index_to_action(self, idx: int) -> Action:
        """Map network output index to Action enum."""
        return self.action_space[idx]
