"""Exploration and Hyperparameter Schedules for DQN (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.2:
- Epsilon-greedy schedule: epsilon_0 = 1.0 -> epsilon_min = 0.05 over 50,000 steps
- PER importance sampling beta schedule: beta_0 = 0.4 -> beta_end = 1.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EpsilonSchedule:
    """Linear epsilon decay schedule for epsilon-greedy exploration."""

    start_epsilon: float = 1.0
    min_epsilon: float = 0.05
    decay_steps: int = 50_000

    def get_value(self, step: int) -> float:
        if step <= 0:
            return self.start_epsilon
        if step >= self.decay_steps:
            return self.min_epsilon
        fraction = step / float(self.decay_steps)
        return self.start_epsilon - fraction * (self.start_epsilon - self.min_epsilon)


@dataclass
class BetaSchedule:
    """Linear annealing schedule for PER importance-sampling exponent beta."""

    start_beta: float = 0.4
    end_beta: float = 1.0
    total_steps: int = 50_000

    def get_value(self, step: int) -> float:
        if step <= 0:
            return self.start_beta
        if step >= self.total_steps:
            return self.end_beta
        fraction = step / float(self.total_steps)
        return self.start_beta + fraction * (self.end_beta - self.start_beta)
