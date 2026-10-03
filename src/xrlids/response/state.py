"""Six-dimensional causal state representation for Phase 2 (Task 3).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 4:
    s_t = [S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t] in R^6

Strict Causal Invariants:
1. NEVER include ground-truth label y_t in observation state.
2. NEVER access future flow arrivals, future timestamps, or future detector scores.
3. State at step t is computed strictly from current flow measurement (v_t), current
   detector risk score (S_t), and historical interactions up to step t-1.
4. All state components are normalized to [0.0, 1.0] (or [-1.0, 1.0] for trajectory).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import numpy as np

from xrlids.response.types import Action


@dataclass
class StateBuilder:
    """Constructs the strictly causal, minimum justified 6D state representation."""

    score_trajectory_k: int = 5
    alert_density_window_w: int = 20
    alert_threshold: float = 0.50
    cooldown_max_steps: int = 30
    step_duration_s: float = 1.0  # Nominal decision step duration (30 steps = 30.0s cooldown)
    volumetric_scale_log_max: float = 8.0  # 10^8 bytes/s (100 MB/s) normalized to 1.0
    disabled_dimensions: Sequence[int] = ()  # For state component ablation experiments

    # Internal causal memory buffers (updated strictly step-by-step)
    _score_history: deque[float] = field(init=False)
    _alert_history: deque[int] = field(init=False)
    _last_action: Action = field(default=Action.ALLOW, init=False)
    _cooldown_remaining: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Reset all historical buffers to initial clean state."""
        self._score_history = deque(maxlen=self.score_trajectory_k)
        self._alert_history = deque(maxlen=self.alert_density_window_w)
        self._last_action = Action.ALLOW
        self._cooldown_remaining = 0

    def build_state(
        self,
        attack_score: float,
        flow_bytes_per_s: float,
        *,
        cooldown_remaining: int | None = None,
        last_action: Action | None = None,
    ) -> np.ndarray:
        """Construct the 6D causal state vector for the current flow arrival.

        Parameters
        ----------
        attack_score: float
            Continuous detector risk score S_t in [0.0, 1.0].
        flow_bytes_per_s: float
            Raw volumetric feature (flow_bytes_per_s >= 0.0).
        cooldown_remaining: int | None
            Override for active cooldown remaining steps; if None, uses internal tracker.
        last_action: Action | None
            Override for previous action a_(t-1); if None, uses internal tracker.

        Returns
        -------
        np.ndarray
            6-dimensional observation vector s_t in R^6.
        """
        # 1. Dimension 0: Current Attack Risk Score S_t in [0.0, 1.0]
        s0 = float(np.clip(attack_score, 0.0, 1.0))

        # 2. Dimension 1: Score Trajectory ΔS_t in [-1.0, 1.0]
        # ΔS_t = S_t - mean(S_{t-k : t-1}). If no history, ΔS_t = 0.0.
        if len(self._score_history) > 0:
            mean_past_score = float(np.mean(self._score_history))
            s1 = float(np.clip(s0 - mean_past_score, -1.0, 1.0))
        else:
            s1 = 0.0

        # 3. Dimension 2: Recent Alert Density N_alert in [0.0, 1.0]
        # Fraction of past W flows exceeding baseline warning threshold (0.50).
        # Note: current score S_t is incorporated to reflect alert status at flow arrival.
        current_alert = 1 if s0 >= self.alert_threshold else 0
        window_alerts = list(self._alert_history) + [current_alert]
        s2 = float(len(window_alerts) and (sum(window_alerts) / len(window_alerts)))
        s2 = float(np.clip(s2, 0.0, 1.0))

        # 4. Dimension 3: Normalized Previous Action a_(t-1) in [0.0, 1.0]
        # Normalized by dividing by 3.0: ALLOW=0.0, ALERT=0.333, RATE_LIMIT=0.667, ISOLATE=1.0.
        prev_act = last_action if last_action is not None else self._last_action
        s3 = float(prev_act.value / 3.0)

        # 5. Dimension 4: Remaining Cooldown Timer Fraction c_t in [0.0, 1.0]
        # Fraction of mandatory cooldown window remaining before de-escalation/re-trigger.
        rem_cool = cooldown_remaining if cooldown_remaining is not None else self._cooldown_remaining
        s4 = float(np.clip(rem_cool / max(1, self.cooldown_max_steps), 0.0, 1.0))

        # 6. Dimension 5: Normalized Coarse Volumetric Scale v_t in [0.0, 1.0]
        # v_t = min(1.0, max(0.0, log10(1.0 + bytes_per_s) / volumetric_scale_log_max))
        bps = max(0.0, float(flow_bytes_per_s))
        s5 = float(np.clip(np.log10(1.0 + bps) / self.volumetric_scale_log_max, 0.0, 1.0))

        state_vector = np.array([s0, s1, s2, s3, s4, s5], dtype=np.float32)
        if self.disabled_dimensions:
            for dim in self.disabled_dimensions:
                if 0 <= dim < 6:
                    state_vector[dim] = 0.0
        return state_vector

    def update_history(
        self,
        attack_score: float,
        enforced_action: Action,
        cooldown_remaining: int,
    ) -> None:
        """Advance causal history buffers after an action has been selected and enforced.

        Parameters
        ----------
        attack_score: float
            Current score S_t to append to past score buffer.
        enforced_action: Action
            Action that was actually enforced by the safety gate at step t.
        cooldown_remaining: int
            Updated remaining cooldown steps.
        """
        s0 = float(np.clip(attack_score, 0.0, 1.0))
        self._score_history.append(s0)
        self._alert_history.append(1 if s0 >= self.alert_threshold else 0)
        self._last_action = enforced_action
        self._cooldown_remaining = max(0, int(cooldown_remaining))
