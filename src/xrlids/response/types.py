"""Response types, actions, and logging structures for Phase 2 (Task 2 & 4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any
import numpy as np


class Action(IntEnum):
    """Discrete, graded autonomous response actions (SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 5)."""

    ALLOW = 0
    ALERT = 1
    RATE_LIMIT = 2
    ISOLATE = 3

    @property
    def token(self) -> str:
        return self.name

    @classmethod
    def from_token(cls, token: str) -> "Action":
        token_upper = token.upper()
        if token_upper in cls.__members__:
            return cls[token_upper]
        raise ValueError(f"Unknown action token: '{token}'; expected one of {list(cls.__members__.keys())}")


class ActionSpaceMode(str, Enum):
    """Action space operating mode for Phase 2 comparison (Section 5.2)."""

    THREE_ACTION = "3-action"  # ALLOW, ALERT, RATE_LIMIT
    FOUR_ACTION = "4-action"   # ALLOW, ALERT, RATE_LIMIT, ISOLATE


@dataclass
class SafetyOverrideRecord:
    """Audit record for a deterministic safety-gate override."""

    step: int
    flow_id: str | int
    host_id: str
    proposed_action: Action
    enforced_action: Action
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "flow_id": str(self.flow_id),
            "host_id": self.host_id,
            "proposed_action": self.proposed_action.name,
            "enforced_action": self.enforced_action.name,
            "reason": self.reason,
        }


@dataclass
class StepLog:
    """Complete per-step execution audit log for simulation and explainability."""

    step: int
    flow_id: str | int
    host_id: str
    true_label: int  # 0: benign, 1: attack (for consequence/evaluation only; NEVER in observation state!)
    attack_score: float  # Continuous detector risk score S_t in [0.0, 1.0]
    state: np.ndarray  # 6-dimensional causal observation vector
    proposed_action: Action
    enforced_action: Action
    overridden: bool
    override_reason: str | None
    base_cost: float
    chattering_penalty: float
    fatigue_penalty: float
    total_cost: float
    reward: float  # -total_cost
    consequences: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "flow_id": str(self.flow_id),
            "host_id": self.host_id,
            "true_label": int(self.true_label),
            "attack_score": float(self.attack_score),
            "state": [float(x) for x in self.state],
            "proposed_action": self.proposed_action.name,
            "enforced_action": self.enforced_action.name,
            "overridden": bool(self.overridden),
            "override_reason": self.override_reason,
            "base_cost": float(self.base_cost),
            "chattering_penalty": float(self.chattering_penalty),
            "fatigue_penalty": float(self.fatigue_penalty),
            "total_cost": float(self.total_cost),
            "reward": float(self.reward),
            "consequences": dict(self.consequences),
        }


StepRecord = StepLog


@dataclass
class EpisodeSummary:
    """Consolidated summary of an offline simulation replay episode."""

    episode_id: str
    total_steps: int
    total_cost: float
    mean_cost: float
    total_reward: float
    action_counts: dict[str, int]
    override_counts: dict[str, int]
    false_quarantine_rate: float
    business_availability_score: float
    action_chattering_index: float
    mitigation_delay: float
    uncontained_attacks: int
    contained_attacks: int
    step_logs: list[StepLog] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "total_steps": self.total_steps,
            "total_cost": float(self.total_cost),
            "mean_cost": float(self.mean_cost),
            "total_reward": float(self.total_reward),
            "action_counts": dict(self.action_counts),
            "override_counts": dict(self.override_counts),
            "false_quarantine_rate": float(self.false_quarantine_rate),
            "business_availability_score": float(self.business_availability_score),
            "action_chattering_index": float(self.action_chattering_index),
            "mitigation_delay": float(self.mitigation_delay),
            "uncontained_attacks": int(self.uncontained_attacks),
            "contained_attacks": int(self.contained_attacks),
        }
