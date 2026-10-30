"""DQN Autonomous Response Service for XRL-IDARS (Phase 10).

Manages policy checkpoint loading, state vector construction via StateBuilder,
Q-value inference via DuelingQNetwork, and policy decision explanations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import time
from typing import Any, Mapping

import numpy as np
import torch

from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_4ACTION_CHECKPOINT = REPO_ROOT / "models" / "dqn" / "dqn_4action_best.pt"
DEFAULT_3ACTION_CHECKPOINT = REPO_ROOT / "models" / "dqn" / "dqn_3action_best.pt"

ACTION_NAMES_4 = {
    Action.ALLOW: "ALLOW (Permit normal traffic)",
    Action.ALERT: "ALERT (Flag to SIEM / log warning)",
    Action.RATE_LIMIT: "RATE_LIMIT (Throttle bandwidth / QoS constraint)",
    Action.ISOLATE: "ISOLATE (Drop packets / quarantine source IP)",
}


@dataclass
class ResponseRecommendation:
    """Standardized autonomous response recommendation output."""

    action: Action
    action_name: str
    action_index: int
    q_values: dict[str, float]
    best_q_value: float
    q_advantage_over_next: float
    state_vector: list[float]  # 6D causal state
    state_components: dict[str, float]
    justification: str
    inference_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.name
        return d


class DQNResponseService:
    """Thread-safe response decision service driven by trained Dueling DQN networks."""

    def __init__(
        self,
        checkpoint_path: str | Path | None = None,
        action_dim: int = 4,
        device: str = "cpu",
    ) -> None:
        self.action_dim = action_dim
        self.device = torch.device(device)
        self.checkpoint_path = Path(
            checkpoint_path
            or (DEFAULT_4ACTION_CHECKPOINT if action_dim == 4 else DEFAULT_3ACTION_CHECKPOINT)
        )

        self.network = DuelingQNetwork(input_dim=6, action_dim=action_dim)
        self._load_checkpoint()
        self.network.to(self.device)
        self.network.eval()

        self._host_builders: dict[str, StateBuilder] = {}

    def _load_checkpoint(self) -> None:
        """Load weights from PyTorch checkpoint."""
        if not self.checkpoint_path.exists():
            raise FileNotFoundError(f"DQN checkpoint not found at: {self.checkpoint_path}")

        ckpt = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)
        if isinstance(ckpt, dict) and "online_net_state_dict" in ckpt:
            self.network.load_state_dict(ckpt["online_net_state_dict"])
        elif isinstance(ckpt, dict) and "state_dict" in ckpt:
            self.network.load_state_dict(ckpt["state_dict"])
        elif isinstance(ckpt, dict):
            self.network.load_state_dict(ckpt)
        else:
            raise ValueError(f"Unexpected checkpoint payload type: {type(ckpt)}")
        logger.info("DQNResponseService successfully loaded checkpoint: %s", self.checkpoint_path)

    def _get_builder(self, host_id: str) -> StateBuilder:
        if host_id not in self._host_builders:
            # Bound dictionary capacity to prevent memory leaks
            if len(self._host_builders) >= 10000:
                self._host_builders.pop(next(iter(self._host_builders)))
            self._host_builders[host_id] = StateBuilder()
        return self._host_builders[host_id]

    def recommend_action(
        self,
        attack_score: float,
        flow_bytes_per_s: float,
        host_id: str = "default",
        last_action: Action | None = None,
        cooldown_remaining: int = 0,
    ) -> ResponseRecommendation:
        """Evaluate flow threat context and recommend optimal response action."""
        t0 = time.perf_counter()
        builder = self._get_builder(host_id)

        # 1. Build 6D causal state vector
        state_vec = builder.build_state(
            attack_score=attack_score,
            flow_bytes_per_s=flow_bytes_per_s,
            cooldown_remaining=cooldown_remaining,
            last_action=last_action,
        )

        # 2. Run DQN forward pass
        state_tensor = torch.from_numpy(state_vec).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_out = self.network(state_tensor).squeeze(0).cpu().numpy()

        # 3. Map Q-values
        actions_list = [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE][:self.action_dim]
        q_dict = {a.name: float(q_out[i]) for i, a in enumerate(actions_list)}

        best_idx = int(np.argmax(q_out))
        best_action = actions_list[best_idx]
        best_q = float(q_out[best_idx])

        # Advantage over next-best action
        sorted_qs = sorted(q_out, reverse=True)
        adv = float(sorted_qs[0] - sorted_qs[1]) if len(sorted_qs) > 1 else 0.0

        # Update host builder causal memory
        builder.update_history(
            attack_score=attack_score,
            enforced_action=best_action,
            cooldown_remaining=cooldown_remaining,
        )

        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0

        # Formulate policy explanation
        justification = (
            f"DQN selected {best_action.name} with expected return Q={best_q:.2f} "
            f"(advantage ΔQ={adv:.2f} over alternative actions). "
            f"State context: threat score S_t={state_vec[0]:.2f}, alert density N_alert={state_vec[2]:.2f}, "
            f"volumetric scale v_t={state_vec[5]:.2f}."
        )

        components = {
            "S_t (Attack Score)": float(state_vec[0]),
            "delta_S_t (Score Trajectory)": float(state_vec[1]),
            "N_alert (Alert Density)": float(state_vec[2]),
            "prev_action": float(state_vec[3]),
            "c_t (Cooldown Fraction)": float(state_vec[4]),
            "v_t (Volumetric Scale)": float(state_vec[5]),
        }

        return ResponseRecommendation(
            action=best_action,
            action_name=ACTION_NAMES_4.get(best_action, best_action.name),
            action_index=best_action.value,
            q_values=q_dict,
            best_q_value=best_q,
            q_advantage_over_next=adv,
            state_vector=[float(x) for x in state_vec],
            state_components=components,
            justification=justification,
            inference_time_ms=elapsed_ms,
        )
