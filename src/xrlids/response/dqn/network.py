"""Dueling Q-Network Architecture for Autonomous Response (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.1:
- Input: 6-dimensional causal state vector s_t
- Backbone: 2-layer MLP (64, 64) with LayerNorm and LeakyReLU activations
- Dueling Streams: Separate scalar Value stream V(s) and Advantage stream A(s, a)
- Dueling aggregation: Q(s, a) = V(s) + (A(s, a) - mean_{a'} A(s, a'))
"""

from __future__ import annotations

import torch
import torch.nn as nn


class DuelingQNetwork(nn.Module):
    """Dueling Deep Q-Network decomposing state value V(s) and action advantage A(s, a)."""

    def __init__(
        self,
        input_dim: int = 6,
        action_dim: int = 4,
        hidden_dim: int = 64,
        negative_slope: float = 0.01,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        self.negative_slope = negative_slope

        # Shared representation backbone
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.ln1 = nn.LayerNorm(hidden_dim)
        self.act1 = nn.LeakyReLU(negative_slope=negative_slope)

        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.ln2 = nn.LayerNorm(hidden_dim)
        self.act2 = nn.LeakyReLU(negative_slope=negative_slope)

        # Value stream: V(s) in R^1
        self.val_fc = nn.Linear(hidden_dim, 32)
        self.val_act = nn.LeakyReLU(negative_slope=negative_slope)
        self.val_out = nn.Linear(32, 1)

        # Advantage stream: A(s, a) in R^{|A|}
        self.adv_fc = nn.Linear(hidden_dim, 32)
        self.adv_act = nn.LeakyReLU(negative_slope=negative_slope)
        self.adv_out = nn.Linear(32, action_dim)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Compute Q(s, a) using dueling decomposition.

        Parameters
        ----------
        state : torch.Tensor
            State tensor of shape (batch_size, input_dim) or (input_dim,).

        Returns
        -------
        torch.Tensor
            Q-values of shape (batch_size, action_dim) or (action_dim,).
        """
        is_single = state.dim() == 1
        if is_single:
            state = state.unsqueeze(0)

        # Feature extraction
        h = self.act1(self.ln1(self.fc1(state)))
        h = self.act2(self.ln2(self.fc2(h)))

        # Value and advantage streams
        v = self.val_out(self.val_act(self.val_fc(h)))  # (batch_size, 1)
        adv = self.adv_out(self.adv_act(self.adv_fc(h)))  # (batch_size, action_dim)

        # Dueling aggregation: Q(s, a) = V(s) + A(s, a) - mean(A(s, :))
        adv_mean = adv.mean(dim=-1, keepdim=True)
        q = v + (adv - adv_mean)

        if is_single:
            return q.squeeze(0)
        return q

    def compute_streams(self, state: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Compute V(s), A(s, a), and Q(s, a) simultaneously for explainability audit."""
        is_single = state.dim() == 1
        if is_single:
            state = state.unsqueeze(0)

        h = self.act1(self.ln1(self.fc1(state)))
        h = self.act2(self.ln2(self.fc2(h)))

        v = self.val_out(self.val_act(self.val_fc(h)))
        adv = self.adv_out(self.adv_act(self.adv_fc(h)))
        adv_mean = adv.mean(dim=-1, keepdim=True)
        q = v + (adv - adv_mean)

        if is_single:
            return v.squeeze(0), adv.squeeze(0), q.squeeze(0)
        return v, adv, q
