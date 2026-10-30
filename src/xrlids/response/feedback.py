"""Reinforcement Learning Outcome Feedback & Experience Logging (Priority 5).

Implements the outcome feedback loop for autonomous response policies:
1. Records (s_t, a_t, r_t, s_{t+1}, done_t) transition tuples.
2. Computes calibrated environmental rewards balancing security containment vs operational disruption.
3. Preserves offline/online separation: production inference uses frozen Q-checkpoints,
   while logged experiences feed Offline Policy Evaluation (OPE) and batch RL refinement.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import threading
from typing import Any, Mapping, Sequence
import numpy as np

from xrlids.response.types import Action
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TRANSITIONS_LOG = REPO_ROOT / "results" / "audits" / "rl_transitions.jsonl"


@dataclass(frozen=True)
class TransitionRecord:
    """Formal (s, a, r, s', done) transition record."""

    transition_id: str
    timestamp: str
    target_host: str
    state_before: list[float]
    action_taken: str
    reward: float
    state_after: list[float]
    done: bool
    verified: bool
    ground_truth_label: int | None = None  # 0=benign, 1=attack (if known post-hoc)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "timestamp": self.timestamp,
            "target_host": self.target_host,
            "state_before": self.state_before,
            "action_taken": self.action_taken,
            "reward": round(self.reward, 4),
            "state_after": self.state_after,
            "done": self.done,
            "verified": self.verified,
            "ground_truth_label": self.ground_truth_label,
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class ResponseOutcomeFeedbackLoop:
    """Records response outcomes, computes rewards, and logs transitions for OPE/retraining."""

    def __init__(
        self,
        buffer_size: int = 10000,
        log_path: Path | str | None = None,
        persist_to_disk: bool = True,
    ) -> None:
        self.buffer_size = buffer_size
        self.persist_to_disk = persist_to_disk
        self.log_path = Path(log_path or DEFAULT_TRANSITIONS_LOG)
        if self.persist_to_disk:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._transitions: deque[TransitionRecord] = deque(maxlen=buffer_size)
        self._total_transitions: int = 0
        self._cumulative_reward: float = 0.0

    @staticmethod
    def calculate_reward(
        action: Action,
        state_before: np.ndarray | Sequence[float],
        verified: bool = True,
        ground_truth: int | None = None,
    ) -> float:
        """Compute empirical environmental reward balancing containment and availability.
        
        State vector layout: [S_t, Delta S_t, N_alert, a_{t-1}, c_t, v_t]
        """
        s = np.asarray(state_before, dtype=float)
        risk_score = float(s[0]) if len(s) > 0 else 0.5
        is_high_risk = risk_score >= 0.70
        is_benign_risk = risk_score < 0.30

        # Base penalty for failed verification
        if not verified:
            return -2.5

        # Reward structure if ground truth is available (e.g., benchmark replay)
        if ground_truth is not None:
            is_attack = bool(ground_truth == 1)
            if is_attack:
                if action == Action.ISOLATE:
                    return 1.2
                elif action == Action.RATE_LIMIT:
                    return 0.8
                elif action == Action.ALERT:
                    return 0.2
                else:  # ALLOW
                    return -1.5
            else:  # Benign traffic
                if action == Action.ALLOW:
                    return 0.2
                elif action == Action.ALERT:
                    return -0.05
                elif action == Action.RATE_LIMIT:
                    return -0.6
                else:  # ISOLATE on benign
                    return -2.0

        # Observational reward when ground truth is unknown (unsupervised operational reward)
        if action == Action.ISOLATE:
            return 1.0 if is_high_risk else -1.5
        elif action == Action.RATE_LIMIT:
            return 0.6 if is_high_risk else -0.4
        elif action == Action.ALERT:
            return 0.1 if is_high_risk else -0.05
        else:  # ALLOW
            return 0.15 if is_benign_risk else -1.0

    def record_transition(
        self,
        target_host: str,
        state_before: np.ndarray | Sequence[float],
        action: Action,
        state_after: np.ndarray | Sequence[float],
        verified: bool = True,
        ground_truth: int | None = None,
        done: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> TransitionRecord:
        """Construct, store, and persist a transition record."""
        import uuid
        tid = f"tr-{uuid.uuid4().hex[:10]}"
        reward = self.calculate_reward(action, state_before, verified=verified, ground_truth=ground_truth)
        
        record = TransitionRecord(
            transition_id=tid,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_host=target_host,
            state_before=[float(x) for x in state_before],
            action_taken=action.name if hasattr(action, "name") else str(action),
            reward=reward,
            state_after=[float(x) for x in state_after],
            done=done,
            verified=verified,
            ground_truth_label=ground_truth,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._transitions.append(record)
            self._total_transitions += 1
            self._cumulative_reward += reward

            if self.persist_to_disk:
                try:
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(record.to_json() + "\n")
                except Exception as e:
                    logger.warning("Could not persist transition to %s: %s", self.log_path, e)

        return record

    def get_recent_transitions(self, limit: int = 50) -> list[TransitionRecord]:
        """Retrieve recent transitions from buffer."""
        with self._lock:
            return list(self._transitions)[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Return transition and reward statistics."""
        with self._lock:
            avg_rew = self._cumulative_reward / max(1, self._total_transitions)
            return {
                "total_transitions": self._total_transitions,
                "cumulative_reward": round(self._cumulative_reward, 4),
                "average_reward": round(avg_rew, 4),
                "buffer_size": len(self._transitions),
            }
