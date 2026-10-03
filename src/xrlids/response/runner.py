"""Phase 2A baseline experiment execution engine (Task 10 & 11).

Executes the complete Phase 2A baseline matrix:
    4 Baselines x 3 Cost Regimes x 2 Action Modes = 24 experimental runs
against the designated policy-development validation population (D_pol_val),
preserving D_pol_test as completely untouched.

Produces structured artifacts:
- Configuration and population isolation metadata
- Baseline performance metrics
- Paired bootstrap statistical comparisons
- Safety-gate override summaries
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
import numpy as np

from xrlids.response.baselines import (
    AlwaysAllowPolicy,
    HeuristicStateMachinePolicy,
    ResponsePolicy,
    SingleThresholdPolicy,
    TwoTierThresholdPolicy,
)
from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.metrics import paired_bootstrap_cost_comparison
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import ActionSpaceMode, EpisodeSummary


def instantiate_baseline_ladder(action_mode: ActionSpaceMode) -> list[ResponsePolicy]:
    """Instantiate the 4 deterministic baselines configured for the given action mode."""
    return [
        AlwaysAllowPolicy(),
        SingleThresholdPolicy(threshold=0.50, action_mode=action_mode),
        TwoTierThresholdPolicy(tau_suspect=0.40, tau_isolate=0.75, action_mode=action_mode),
        HeuristicStateMachinePolicy(action_mode=action_mode),
    ]


def run_phase2a_matrix(
    flows: list[FlowRecord],
    *,
    regimes: Sequence[CostRegime] = (
        CostRegime.STANDARD_ENTERPRISE,
        CostRegime.HIGH_AVAILABILITY,
        CostRegime.HIGH_SECURITY_ENCLAVE,
    ),
    action_modes: Sequence[ActionSpaceMode] = (
        ActionSpaceMode.FOUR_ACTION,
        ActionSpaceMode.THREE_ACTION,
    ),
    n_bootstraps: int = 1000,
    seed: int = 42,
) -> dict[str, Any]:
    """Execute the complete Phase 2A evaluation matrix across all regimes and baselines.

    Parameters
    ----------
    flows: list[FlowRecord]
        Ordered flow stream from D_pol_val.
    regimes: Sequence[CostRegime]
        List of cost regimes to evaluate.
    action_modes: Sequence[ActionSpaceMode]
        List of action modes (3-action and 4-action).
    n_bootstraps: int
        Number of bootstrap iterations for paired tests.
    seed: int
        Reproducible random seed.

    Returns
    -------
    dict[str, Any]
        Complete structured results dictionary.
    """
    matrix_results: dict[str, Any] = {}
    runs_summary: list[dict[str, Any]] = []
    comparisons_summary: list[dict[str, Any]] = []

    for mode in action_modes:
        mode_key = mode.value
        matrix_results[mode_key] = {}

        for regime in regimes:
            regime_key = regime.value
            cost_engine = ResearchCostEngine(regime=regime)
            policies = instantiate_baseline_ladder(mode)

            regime_run_data: dict[str, Any] = {
                "regime": regime_key,
                "action_mode": mode_key,
                "cost_matrix_assumptions": cost_engine.to_dict(),
                "baselines": {},
            }

            episode_summaries: dict[str, EpisodeSummary] = {}
            policy_costs: dict[str, list[float]] = {}

            # Execute all 4 baselines on identical flows
            for policy in policies:
                safety_gate = DeterministicSafetyGate(action_mode=mode)
                state_builder = StateBuilder()

                sim = OfflineResponseSimulator(
                    flows=flows,
                    cost_engine=cost_engine,
                    safety_gate=safety_gate,
                    state_builder=state_builder,
                    action_mode=mode,
                    random_seed=seed,
                )

                summary = sim.run_policy(policy, episode_id=f"{mode_key}_{regime_key}_{policy.name}")
                episode_summaries[policy.name] = summary
                costs_array = [log.total_cost for log in summary.step_logs]
                policy_costs[policy.name] = costs_array

                run_entry = {
                    "action_mode": mode_key,
                    "cost_regime": regime_key,
                    "policy_name": policy.name,
                    "total_flows": summary.total_steps,
                    "total_cost": summary.total_cost,
                    "mean_cost_per_flow": summary.mean_cost,
                    "false_quarantine_rate": summary.false_quarantine_rate,
                    "business_availability_score_pct": summary.business_availability_score,
                    "action_chattering_index": summary.action_chattering_index,
                    "mitigation_delay_steps": summary.mitigation_delay,
                    "action_counts": summary.action_counts,
                    "override_counts": summary.override_counts,
                    "uncontained_attacks": summary.uncontained_attacks,
                    "contained_attacks": summary.contained_attacks,
                }
                regime_run_data["baselines"][policy.name] = run_entry
                runs_summary.append(run_entry)

            # Perform paired bootstrap hypothesis tests
            # 1. Compare all against Baseline 0 (Always ALLOW)
            base0_name = policies[0].name
            base0_costs = policy_costs[base0_name]

            # 2. Compare against Baseline 1 (Single Threshold 0.50)
            base1_name = policies[1].name
            base1_costs = policy_costs[base1_name]

            regime_comparisons: list[dict[str, Any]] = []

            for p in policies[1:]:
                # vs Baseline 0
                comp_vs_0 = paired_bootstrap_cost_comparison(
                    costs_baseline=base0_costs,
                    costs_candidate=policy_costs[p.name],
                    baseline_name=base0_name,
                    candidate_name=p.name,
                    n_bootstraps=n_bootstraps,
                    seed=seed,
                )
                comp_vs_0["action_mode"] = mode_key
                comp_vs_0["cost_regime"] = regime_key
                regime_comparisons.append(comp_vs_0)
                comparisons_summary.append(comp_vs_0)

            for p in policies[2:]:
                # vs Baseline 1
                comp_vs_1 = paired_bootstrap_cost_comparison(
                    costs_baseline=base1_costs,
                    costs_candidate=policy_costs[p.name],
                    baseline_name=base1_name,
                    candidate_name=p.name,
                    n_bootstraps=n_bootstraps,
                    seed=seed,
                )
                comp_vs_1["action_mode"] = mode_key
                comp_vs_1["cost_regime"] = regime_key
                regime_comparisons.append(comp_vs_1)
                comparisons_summary.append(comp_vs_1)

            regime_run_data["paired_comparisons"] = regime_comparisons
            matrix_results[mode_key][regime_key] = regime_run_data

    return {
        "action_modes": [m.value for m in action_modes],
        "cost_regimes": [r.value for r in regimes],
        "total_configurations": len(runs_summary),
        "total_comparisons": len(comparisons_summary),
        "runs": runs_summary,
        "comparisons": comparisons_summary,
        "matrix_tree": matrix_results,
    }
