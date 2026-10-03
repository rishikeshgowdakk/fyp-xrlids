"""Phase 2 Explainable Autonomous Response Layer (XRL-IDARS).

Provides offline flow replay, deterministic safety gates, research cost engines,
and deterministic baseline policies as specified in SPEC-P2-AUTONOMOUS-RESPONSE-001.
"""

from __future__ import annotations

from xrlids.response.baselines import (
    AlwaysAllowPolicy,
    HeuristicStateMachinePolicy,
    ResponsePolicy,
    SingleThresholdPolicy,
    TwoTierThresholdPolicy,
)
from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.detector import FrozenDetector
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.isolation import (
    PolicySplitManifest,
    partition_policy_development_population,
)
from xrlids.response.metrics import (
    compute_action_chattering_index,
    compute_business_availability_score,
    compute_cumulative_cost,
    compute_false_quarantine_rate,
    compute_mean_cost,
    compute_mitigation_delay,
    compute_relative_cost_reduction,
    evaluate_response_run,
    paired_bootstrap_cost_comparison,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import (
    Action,
    ActionSpaceMode,
    EpisodeSummary,
    SafetyOverrideRecord,
    StepLog,
)

__all__ = [
    "Action",
    "ActionSpaceMode",
    "SafetyOverrideRecord",
    "StepLog",
    "EpisodeSummary",
    "StateBuilder",
    "DeterministicSafetyGate",
    "CostRegime",
    "ResearchCostEngine",
    "ResponsePolicy",
    "AlwaysAllowPolicy",
    "SingleThresholdPolicy",
    "TwoTierThresholdPolicy",
    "HeuristicStateMachinePolicy",
    "FlowRecord",
    "OfflineResponseSimulator",
    "PolicySplitManifest",
    "partition_policy_development_population",
    "FrozenDetector",
    "compute_cumulative_cost",
    "compute_mean_cost",
    "compute_false_quarantine_rate",
    "compute_action_chattering_index",
    "compute_business_availability_score",
    "compute_mitigation_delay",
    "compute_relative_cost_reduction",
    "evaluate_response_run",
    "paired_bootstrap_cost_comparison",
]
