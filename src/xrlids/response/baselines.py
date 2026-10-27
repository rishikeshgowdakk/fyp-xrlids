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
import math
from typing import Any
import numpy as np

from xrlids.response.costs import CostRegime, RESEARCH_COST_MATRICES
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


@dataclass
class CostOptimalThresholdPolicy(ResponsePolicy):
    """Baseline 4: Cost-optimal decision policy with respect to detector score.

    Under an operational cost matrix C(a, y) (where y in {0: benign, 1: attack}),
    the expected operational loss of action a for an assumed attack probability p is:
        E[Loss(a) | p] = (1 - p) * C(a, 0) + p * C(a, 1)

    The unconstrained optimal action is:
        a*(p) = argmin_{a in A} E[Loss(a) | p]

    CRITICAL SCIENTIFIC FRAMING:
    This policy is cost-optimal strictly with respect to the input detector score under
    an assumed-probability model S_t ≈ P(y=1|x).
    Because raw detector scores (e.g. Random Forest leaf voting fractions) are not proven
    calibrated posterior probabilities, this policy must NOT be represented as a proven
    true Bayes-optimal policy on uncalibrated outputs.
    """

    name: str = "Baseline_4_Cost_Optimal_Threshold"
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    cost_regime: CostRegime = CostRegime.STANDARD_ENTERPRISE
    cost_matrix: dict[int, dict[Action, float]] | None = None
    clip_out_of_bounds: bool = True
    tie_breaker: str = "conservative"  # 'conservative' (min action.value) or 'aggressive' (max action.value)

    def __post_init__(self) -> None:
        if self.cost_matrix is None:
            self.cost_matrix = RESEARCH_COST_MATRICES[self.cost_regime]
        if 0 not in self.cost_matrix or 1 not in self.cost_matrix:
            raise ValueError("cost_matrix must contain entries for ground truth labels 0 and 1.")

    def expected_cost(self, action: Action, attack_score: float) -> float:
        """Compute expected cost of a single action given attack score p in [0, 1]."""
        p = self._validate_and_sanitize_score(attack_score)
        c0 = float(self.cost_matrix[0].get(action, 0.0))
        c1 = float(self.cost_matrix[1].get(action, 0.0))
        return (1.0 - p) * c0 + p * c1

    def _validate_and_sanitize_score(self, attack_score: float) -> float:
        """Validate input attack score, detecting NaNs, infinities, and bounds."""
        if math.isnan(attack_score):
            raise ValueError("Invalid attack_score: NaN is not a valid score.")
        if math.isinf(attack_score):
            raise ValueError("Invalid attack_score: infinite values are not permitted.")

        p = float(attack_score)
        if p < 0.0 or p > 1.0:
            if self.clip_out_of_bounds:
                p = float(np.clip(p, 0.0, 1.0))
            else:
                raise ValueError(f"attack_score must be in [0.0, 1.0], got {attack_score}")
        return p

    def get_allowed_actions(self) -> list[Action]:
        """Return list of permitted actions for the current action mode."""
        if self.action_mode == ActionSpaceMode.THREE_ACTION:
            return [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT]
        return [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE]

    def predict_unconstrained_action(self, attack_score: float) -> Action:
        """Select action that strictly minimizes expected cost for the given score.

        Separates the unconstrained decision from any downstream safety gate invariants.
        """
        p = self._validate_and_sanitize_score(attack_score)
        allowed = self.get_allowed_actions()

        best_action = allowed[0]
        min_cost = float("inf")

        # Evaluate expected cost across allowed actions
        # Handle ties with configured tie-breaking policy
        tolerance = 1e-9
        candidate_actions: list[Action] = []

        for act in allowed:
            cost = (1.0 - p) * self.cost_matrix[0].get(act, 0.0) + p * self.cost_matrix[1].get(act, 0.0)
            if cost < min_cost - tolerance:
                min_cost = cost
                candidate_actions = [act]
            elif abs(cost - min_cost) <= tolerance:
                candidate_actions.append(act)

        if len(candidate_actions) == 1:
            return candidate_actions[0]

        # Break ties deterministically
        if self.tie_breaker == "aggressive":
            return max(candidate_actions, key=lambda a: a.value)
        else:  # 'conservative' (default): prefer least disruptive action
            return min(candidate_actions, key=lambda a: a.value)

    def predict_action(
        self,
        state: np.ndarray,
        attack_score: float,
        host_id: str | None = None,
    ) -> Action:
        """Standard ResponsePolicy entrypoint returning cost-optimal action."""
        return self.predict_unconstrained_action(attack_score)

    def derive_threshold_boundaries(self) -> list[dict[str, Any]]:
        """Dynamically derive analytical threshold switching intervals on [0.0, 1.0].

        Returns
        -------
        list[dict[str, Any]]
            Ordered list of dicts with keys 'lower', 'upper', and 'action'.
        """
        allowed = self.get_allowed_actions()
        crit_points = [0.0, 1.0]

        # Calculate all pairwise intersection points in [0, 1]
        for i in range(len(allowed)):
            for j in range(i + 1, len(allowed)):
                a, b = allowed[i], allowed[j]
                c0_a, c1_a = self.cost_matrix[0].get(a, 0.0), self.cost_matrix[1].get(a, 0.0)
                c0_b, c1_b = self.cost_matrix[0].get(b, 0.0), self.cost_matrix[1].get(b, 0.0)
                denom = (c0_b - c0_a) + (c1_a - c1_b)
                if abs(denom) > 1e-12:
                    p_inter = (c0_b - c0_a) / denom
                    if 0.0 <= p_inter <= 1.0:
                        crit_points.append(p_inter)

        # Deduplicate and sort critical points
        sorted_points = sorted(list(set([round(p, 9) for p in crit_points])))

        intervals: list[dict[str, Any]] = []
        for k in range(len(sorted_points) - 1):
            low = sorted_points[k]
            high = sorted_points[k + 1]
            p_mid = (low + high) / 2.0
            act = self.predict_unconstrained_action(p_mid)
            intervals.append({"lower": low, "upper": high, "action": act})

        # Merge adjacent intervals with identical optimal action
        merged: list[dict[str, Any]] = []
        for interval in intervals:
            if merged and merged[-1]["action"] == interval["action"]:
                merged[-1]["upper"] = interval["upper"]
            else:
                merged.append(interval)

        return merged

    def reset(self) -> None:
        pass

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.name,
            "action_mode": self.action_mode.value,
            "cost_regime": self.cost_regime.value,
            "tie_breaker": self.tie_breaker,
            "clip_out_of_bounds": self.clip_out_of_bounds,
            "threshold_intervals": [
                {"lower": b["lower"], "upper": b["upper"], "action": b["action"].name}
                for b in self.derive_threshold_boundaries()
            ],
            "scientific_note": (
                "Cost-optimal decision policy with respect to detector score under an "
                "assumed-probability model. Not claimed to be a true Bayes-optimal policy "
                "on uncalibrated detector outputs."
            ),
        }
