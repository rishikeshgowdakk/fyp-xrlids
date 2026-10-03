"""Illustrative research cost and reward engine for Phase 2 (Task 6).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 7:
    Composite Step Reward:
    R(s_t, a_t, y_t) = -[ C(a_t, y_t) + C_chatter(a_t, a_(t-1)) + C_fatigue ]

Important Research Framing:
All scalar cost values in this module are explicit RESEARCH ASSUMPTIONS established
to evaluate response policies under controlled asymmetric-loss gradients. They do NOT
represent real enterprise financial costs, and they do NOT select or resolve real
deployment thresholds under Decision D-003. Real deployments require site-specific
empirical cost calibration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from xrlids.response.types import Action


class CostRegime(str, Enum):
    """Parameterized operational research regimes for sensitivity analysis (Section 7.4)."""

    STANDARD_ENTERPRISE = "standard_enterprise"
    HIGH_AVAILABILITY = "high_availability"
    HIGH_SECURITY_ENCLAVE = "high_security_enclave"


# Research assumption cost matrices (dimensionless research loss units)
# [ground_truth_label][action] -> loss
RESEARCH_COST_MATRICES: dict[CostRegime, dict[int, dict[Action, float]]] = {
    CostRegime.STANDARD_ENTERPRISE: {
        0: {  # Benign
            Action.ALLOW: 0.0,
            Action.ALERT: 1.0,
            Action.RATE_LIMIT: 15.0,
            Action.ISOLATE: 60.0,
        },
        1: {  # Attack
            Action.ALLOW: 100.0,
            Action.ALERT: 12.0,
            Action.RATE_LIMIT: 6.0,
            Action.ISOLATE: 2.0,
        },
    },
    CostRegime.HIGH_AVAILABILITY: {
        0: {  # Benign: severe penalty for availability disruption
            Action.ALLOW: 0.0,
            Action.ALERT: 1.0,
            Action.RATE_LIMIT: 30.0,
            Action.ISOLATE: 120.0,
        },
        1: {  # Attack: moderated penalty for breach
            Action.ALLOW: 50.0,
            Action.ALERT: 12.0,
            Action.RATE_LIMIT: 6.0,
            Action.ISOLATE: 2.0,
        },
    },
    CostRegime.HIGH_SECURITY_ENCLAVE: {
        0: {  # Benign: low tolerance for disruption compared to breach
            Action.ALLOW: 0.0,
            Action.ALERT: 1.0,
            Action.RATE_LIMIT: 5.0,
            Action.ISOLATE: 25.0,
        },
        1: {  # Attack: catastrophic penalty for uncontained breach
            Action.ALLOW: 500.0,
            Action.ALERT: 20.0,
            Action.RATE_LIMIT: 10.0,
            Action.ISOLATE: 2.0,
        },
    },
}


@dataclass
class ResearchCostEngine:
    """Evaluates operational response costs and RL step rewards under research assumptions."""

    regime: CostRegime = CostRegime.STANDARD_ENTERPRISE
    custom_matrix: dict[int, dict[Action, float]] | None = None
    chattering_penalty_cost: float = 10.0
    chattering_action_delta_threshold: int = 2
    fatigue_threshold: int = 5
    fatigue_penalty_slope: float = 0.5

    def __post_init__(self) -> None:
        if self.custom_matrix is not None:
            self._matrix = self.custom_matrix
        else:
            self._matrix = RESEARCH_COST_MATRICES[self.regime]

    def compute_base_cost(self, action: Action, y_true: int) -> float:
        """Compute static base cost for the enforced action given ground truth."""
        label_key = 1 if y_true == 1 else 0
        return float(self._matrix[label_key][action])

    def compute_chattering_penalty(
        self,
        action: Action,
        prev_action: Action,
        in_cooldown: bool,
    ) -> float:
        """Compute action chattering penalty for violent policy oscillation during cooldown."""
        delta = abs(action.value - prev_action.value)
        if in_cooldown and delta >= self.chattering_action_delta_threshold:
            return self.chattering_penalty_cost
        return 0.0

    def compute_fatigue_penalty(self, consecutive_alerts: int) -> float:
        """Compute analyst alert fatigue penalty for uncontained sustained alerts."""
        excess_alerts = max(0, consecutive_alerts - self.fatigue_threshold)
        return float(excess_alerts * self.fatigue_penalty_slope)

    def evaluate_step(
        self,
        action: Action,
        y_true: int,
        prev_action: Action,
        in_cooldown: bool,
        consecutive_alerts: int,
    ) -> tuple[float, float, float, float, float]:
        """Compute complete step cost breakdown and reward.

        Returns
        -------
        tuple[float, float, float, float, float]
            (base_cost, chattering_penalty, fatigue_penalty, total_cost, reward)
            where reward = -total_cost.
        """
        base = self.compute_base_cost(action, y_true)
        chatter = self.compute_chattering_penalty(action, prev_action, in_cooldown)
        fatigue = self.compute_fatigue_penalty(consecutive_alerts)
        total_cost = base + chatter + fatigue
        reward = -total_cost
        return base, chatter, fatigue, total_cost, reward

    def to_dict(self) -> dict[str, Any]:
        """Export cost engine configuration for metadata and provenance."""
        serializable_matrix = {
            "benign": {act.name: val for act, val in self._matrix[0].items()},
            "attack": {act.name: val for act, val in self._matrix[1].items()},
        }
        return {
            "regime": self.regime.value,
            "cost_matrix_research_assumptions": serializable_matrix,
            "chattering_penalty_cost": self.chattering_penalty_cost,
            "chattering_action_delta_threshold": self.chattering_action_delta_threshold,
            "fatigue_threshold": self.fatigue_threshold,
            "fatigue_penalty_slope": self.fatigue_penalty_slope,
        }
