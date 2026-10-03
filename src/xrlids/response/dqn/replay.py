"""Prioritized and Uniform Experience Replay Buffers (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.2:
- Prioritized Experience Replay (PER, Schaul et al., 2015)
- Capacity: 100,000 transitions
- alpha_per: 0.6
- beta_per: 0.4 -> 1.0 annealing
- SumTree for O(log N) priority sampling and updates
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
import numpy as np
import torch


@dataclass
class Transition:
    """Single environmental transition tuple."""

    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class SumTree:
    """Binary SumTree data structure for O(log N) prefix-sum sampling and updates."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.tree = np.zeros(2 * capacity, dtype=np.float64)
        self.data: list[Transition | None] = [None] * capacity
        self.write_idx = 0
        self.size = 0

    def total_priority(self) -> float:
        return float(self.tree[1])

    def max_priority(self) -> float:
        if self.size == 0:
            return 1.0
        # Priority leaves are stored at indices [capacity, capacity + size)
        priorities = self.tree[self.capacity : self.capacity + self.size]
        max_p = float(np.max(priorities))
        return max_p if max_p > 0.0 else 1.0

    def update(self, tree_idx: int, priority: float) -> None:
        change = priority - self.tree[tree_idx]
        self.tree[tree_idx] = priority
        idx = tree_idx // 2
        while idx >= 1:
            self.tree[idx] += change
            idx //= 2

    def add(self, priority: float, data: Transition) -> int:
        tree_idx = self.write_idx + self.capacity
        self.data[self.write_idx] = data
        self.update(tree_idx, priority)

        self.write_idx = (self.write_idx + 1) % self.capacity
        if self.size < self.capacity:
            self.size += 1
        return tree_idx

    def get_leaf(self, value: float) -> tuple[int, float, Transition]:
        parent_idx = 1
        while True:
            left_child_idx = 2 * parent_idx
            right_child_idx = left_child_idx + 1

            if left_child_idx >= len(self.tree):
                leaf_idx = parent_idx
                break

            left_sum = self.tree[left_child_idx]
            if value <= left_sum or right_child_idx >= len(self.tree):
                parent_idx = left_child_idx
            else:
                value -= left_sum
                parent_idx = right_child_idx

        data_idx = leaf_idx - self.capacity
        trans = self.data[data_idx]
        assert trans is not None, f"Retrieved empty transition at data_idx {data_idx}"
        return leaf_idx, float(self.tree[leaf_idx]), trans


class PrioritizedReplayBuffer:
    """Prioritized Experience Replay (PER) buffer with importance sampling weights."""

    def __init__(
        self,
        capacity: int = 100_000,
        alpha: float = 0.6,
        eps: float = 1e-6,
    ) -> None:
        self.capacity = capacity
        self.alpha = alpha
        self.eps = eps
        self.tree = SumTree(capacity)

    def __len__(self) -> int:
        return self.tree.size

    def push(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool,
    ) -> None:
        """Store a new transition with maximal priority to guarantee initial exploration."""
        max_priority = self.tree.max_priority()
        trans = Transition(
            state=np.asarray(state, dtype=np.float32),
            action=int(action),
            reward=float(reward),
            next_state=np.asarray(next_state, dtype=np.float32),
            done=bool(done),
        )
        self.tree.add(max_priority, trans)

    def sample(
        self,
        batch_size: int,
        beta: float = 0.4,
    ) -> tuple[dict[str, torch.Tensor], np.ndarray, torch.Tensor]:
        """Sample a batch of transitions proportionally to priorities with importance weights.

        Parameters
        ----------
        batch_size : int
            Number of samples to draw.
        beta : float
            Importance sampling exponent in [0.0, 1.0].

        Returns
        -------
        batch : dict[str, torch.Tensor]
            Tensors for 'states', 'actions', 'rewards', 'next_states', 'dones'.
        tree_indices : np.ndarray
            Tree node indices for later priority updating.
        weights : torch.Tensor
            Normalized importance sampling weights of shape (batch_size, 1).
        """
        assert len(self) >= batch_size, f"Buffer contains {len(self)} < batch_size {batch_size}"

        tree_indices = np.empty(batch_size, dtype=np.int64)
        transitions: list[Transition] = []
        priorities = np.empty(batch_size, dtype=np.float64)

        total_p = self.tree.total_priority()
        segment = total_p / batch_size

        for i in range(batch_size):
            a = segment * i
            b = segment * (i + 1)
            v = np.random.uniform(a, b)
            idx, priority, trans = self.tree.get_leaf(v)
            tree_indices[i] = idx
            priorities[i] = priority
            transitions.append(trans)

        # Sampling probabilities P(i)
        probs = priorities / (total_p + self.eps)

        # Importance-sampling weights: w_i = (N * P(i))^(-beta)
        weights = (len(self) * probs) ** (-beta)
        # Normalize by max weight for stability
        weights = weights / (weights.max() + self.eps)

        states = torch.as_tensor(np.array([t.state for t in transitions]), dtype=torch.float32)
        actions = torch.as_tensor(np.array([t.action for t in transitions]), dtype=torch.int64)
        rewards = torch.as_tensor(np.array([t.reward for t in transitions]), dtype=torch.float32).unsqueeze(1)
        next_states = torch.as_tensor(np.array([t.next_state for t in transitions]), dtype=torch.float32)
        dones = torch.as_tensor(np.array([t.done for t in transitions]), dtype=torch.float32).unsqueeze(1)
        weights_t = torch.as_tensor(weights, dtype=torch.float32).unsqueeze(1)

        batch = {
            "states": states,
            "actions": actions,
            "rewards": rewards,
            "next_states": next_states,
            "dones": dones,
        }
        return batch, tree_indices, weights_t

    def update_priorities(self, tree_indices: Sequence[int], td_errors: np.ndarray | torch.Tensor) -> None:
        """Update sample priorities based on absolute Bellman TD errors."""
        if isinstance(td_errors, torch.Tensor):
            td_errors = td_errors.detach().cpu().numpy()
        td_errors = np.asarray(td_errors).flatten()

        for idx, err in zip(tree_indices, td_errors):
            p = (abs(float(err)) + self.eps) ** self.alpha
            self.tree.update(int(idx), p)
