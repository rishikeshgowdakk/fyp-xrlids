"""Deterministic baseline policies for autonomous response (Task 7).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 8:
    Level 0: Always-ALLOW Policy (Zero Automated Defense)
    Level 1: Deterministic Single-Threshold Policy (τ = 0.50 Research Boundary)
    Level 2: Exploratory Two-Tier Static Threshold Policy (0.40 / 0.75)
    Level 3: Deterministic Rule-Based State Machine

Important Governance Note:
Baselines 1 and 2 are experimental comparators for evaluating multi-tier graded actions
against single thresholds. Neither constitutes a Decision D-003 deployment-threshold decision;
real operational threshold selection remains open pending site-specific cost evidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any
import numpy as np

from xrlids.response.types import Action, ActionSpaceMode


class ResponsePolicy(ABC):
    """Abstract interface for autonomous response policies."""

    name: str

    @abstractmethod
    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        """Select an action given current observation state and continuous attack score."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset internal policy state between episodes/runs."""
        pass

    def to_dict(self) -> dict[str, Any]:
        return {"policy_name": self.name}


@dataclass
class AlwaysAllowPolicy(ResponsePolicy):
    """Baseline 0: Passive policy that permits all traffic unconditionally."""

    name: str = "Baseline_0_Always_ALLOW"

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        return Action.ALLOW

    def reset(self) -> None:
        pass


@dataclass
class SingleThresholdPolicy(ResponsePolicy):
    """Baseline 1: Deterministic single-threshold comparator using frozen research reporting boundary (τ = 0.50)."""

    name: str = "Baseline_1_Single_Threshold_tau_0.50"
    threshold: float = 0.50
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        if attack_score >= self.threshold:
            return Action.RATE_LIMIT if self.action_mode == ActionSpaceMode.THREE_ACTION else Action.ISOLATE
        return Action.ALLOW

    def reset(self) -> None:
        pass

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.name,
            "threshold": self.threshold,
            "action_mode": self.action_mode.value,
            "governance_note": "Experimental comparator using frozen research boundary τ=0.50; not a deployment decision",
        }


@dataclass
class TwoTierThresholdPolicy(ResponsePolicy):
    """Baseline 2: Exploratory two-tier static threshold comparator (τ_1 = 0.40, τ_2 = 0.75)."""

    name: str = "Baseline_2_Two_Tier_0.40_0.75"
    tau_suspect: float = 0.40  # Proposed Phase 2 candidate operating point
    tau_isolate: float = 0.75  # High-confidence attack (min-FPR validation candidate)
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        if self.action_mode == ActionSpaceMode.THREE_ACTION:
            if attack_score >= self.tau_isolate:
                return Action.RATE_LIMIT
            elif attack_score >= self.tau_suspect:
                return Action.ALERT
            return Action.ALLOW
        else:
            if attack_score >= self.tau_isolate:
                return Action.ISOLATE
            elif attack_score >= self.tau_suspect:
                return Action.RATE_LIMIT
            return Action.ALLOW

    def reset(self) -> None:
        pass

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.name,
            "tau_suspect": self.tau_suspect,
            "tau_isolate": self.tau_isolate,
            "action_mode": self.action_mode.value,
            "governance_note": "Exploratory two-tier comparator; not a D-003 deployment-threshold decision",
        }


@dataclass
class HostStateRecord:
    """State memory for a single endpoint in the heuristic state machine."""

    current_tier: Action = Action.ALLOW
    alert_history: deque[int] = field(default_factory=lambda: deque(maxlen=10))
    cooldown_remaining: int = 0


@dataclass
class HeuristicStateMachinePolicy(ResponsePolicy):
    """Baseline 3: Deterministic state machine with memory, multi-tier escalation, and cooldown."""

    name: str = "Baseline_3_Heuristic_State_Machine"
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    tau_suspect: float = 0.40
    tau_high_risk: float = 0.85
    tau_persistent_attack: float = 0.70
    alert_density_threshold: int = 3  # Escalates to RATE_LIMIT if >= 3 alerts in past 10 flows
    cooldown_steps: int = 30

    _hosts: dict[str, HostStateRecord] = field(default_factory=dict, init=False)

    def reset(self) -> None:
        self._hosts.clear()

    def _get_host_state(self, host_id: str) -> HostStateRecord:
        if host_id not in self._hosts:
            self._hosts[host_id] = HostStateRecord(cooldown_remaining=0)
        return self._hosts[host_id]

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        h_id = host_id or "default_session"
        h = self._get_host_state(h_id)

        # Decrement internal cooldown
        if h.cooldown_remaining > 0:
            h.cooldown_remaining -= 1

        is_alert = 1 if attack_score >= self.tau_suspect else 0
        h.alert_history.append(is_alert)
        recent_alert_count = sum(h.alert_history)

        current = h.current_tier

        # Escalation / De-escalation State Machine
        if current == Action.ALLOW:
            if attack_score >= self.tau_high_risk:
                next_action = Action.RATE_LIMIT if self.action_mode == ActionSpaceMode.THREE_ACTION else Action.ISOLATE
                h.cooldown_remaining = self.cooldown_steps
            elif attack_score >= self.tau_suspect:
                next_action = Action.ALERT
            else:
                next_action = Action.ALLOW

        elif current == Action.ALERT:
            if attack_score >= self.tau_high_risk:
                next_action = Action.RATE_LIMIT if self.action_mode == ActionSpaceMode.THREE_ACTION else Action.ISOLATE
                h.cooldown_remaining = self.cooldown_steps
            elif recent_alert_count >= self.alert_density_threshold:
                next_action = Action.RATE_LIMIT
                h.cooldown_remaining = self.cooldown_steps
            elif attack_score < self.tau_suspect and recent_alert_count == 0:
                next_action = Action.ALLOW
            else:
                next_action = Action.ALERT

        elif current == Action.RATE_LIMIT:
            if self.action_mode == ActionSpaceMode.FOUR_ACTION and attack_score >= self.tau_high_risk:
                next_action = Action.ISOLATE
                h.cooldown_remaining = self.cooldown_steps
            elif self.action_mode == ActionSpaceMode.FOUR_ACTION and recent_alert_count >= 5 and attack_score >= self.tau_persistent_attack:
                next_action = Action.ISOLATE
                h.cooldown_remaining = self.cooldown_steps
            elif h.cooldown_remaining == 0 and attack_score < self.tau_suspect and recent_alert_count == 0:
                next_action = Action.ALERT
            else:
                next_action = Action.RATE_LIMIT

        elif current == Action.ISOLATE:
            if h.cooldown_remaining == 0 and attack_score < self.tau_suspect:
                next_action = Action.RATE_LIMIT
                h.cooldown_remaining = self.cooldown_steps // 2
            else:
                next_action = Action.ISOLATE
        else:
            next_action = Action.ALLOW

        # Enforce 3-action mode clamp if needed
        if self.action_mode == ActionSpaceMode.THREE_ACTION and next_action == Action.ISOLATE:
            next_action = Action.RATE_LIMIT

        h.current_tier = next_action
        return next_action

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.name,
            "action_mode": self.action_mode.value,
            "tau_suspect": self.tau_suspect,
            "tau_high_risk": self.tau_high_risk,
            "tau_persistent_attack": self.tau_persistent_attack,
            "alert_density_threshold": self.alert_density_threshold,
            "cooldown_steps": self.cooldown_steps,
        }
