"""Deep Q-Network Autonomous Response Package (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Phase 2B Reinforcement Learning candidate:
- DuelingQNetwork: Value and Advantage stream decomposition
- PrioritizedReplayBuffer: PER with SumTree and importance sampling
- DqnAgent: Epsilon-greedy action selection and prioritized Huber training
- DqnPolicy: Adapter for OfflineResponseSimulator evaluation
- CheckpointManager: Validation-based checkpoint tracking and model selection
- DqnTrainer: Training loop with episode boundary enforcement
"""

from xrlids.response.dqn.agent import DqnAgent
from xrlids.response.dqn.checkpointing import CheckpointManager
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.dqn.policy import DqnPolicy
from xrlids.response.dqn.replay import PrioritizedReplayBuffer, Transition
from xrlids.response.dqn.reproducibility import capture_provenance, set_seed
from xrlids.response.dqn.schedule import BetaSchedule, EpsilonSchedule
from xrlids.response.dqn.target_update import hard_update, soft_update
from xrlids.response.dqn.trainer import DqnTrainer, TrainingConfig

__all__ = [
    "DuelingQNetwork",
    "Transition",
    "PrioritizedReplayBuffer",
    "EpsilonSchedule",
    "BetaSchedule",
    "soft_update",
    "hard_update",
    "set_seed",
    "capture_provenance",
    "CheckpointManager",
    "DqnAgent",
    "DqnPolicy",
    "TrainingConfig",
    "DqnTrainer",
]
