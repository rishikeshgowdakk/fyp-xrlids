#!/usr/bin/env python
"""Comparative Policy Benchmark Subsystem.

Benchmarks Track B1 (Binary DQN), Track B2 (Attack-Aware DQN), and Deterministic
Rule Baselines across:
- Mean cost per flow & relative cost reduction
- Attack containment rate (%)
- False quarantine rate (%)
- Business availability score (%)
- Mitigation delay (steps to containment)
- Action chattering index
- Per-attack-family response breakdown
- Paired bootstrap hypothesis tests (B=1,000 resamples) with 95% CIs and p-values
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

# Ensure src is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

import joblib
import numpy as np
import torch

from xrlids.models.multiclass_detector import MulticlassAttackClassifier
from xrlids.response.baselines import (
    AlwaysAllowPolicy,
    HeuristicStateMachinePolicy,
    ResponsePolicy,
    TwoTierThresholdPolicy,
)
from xrlids.response.costs import AttackAwareCostEngine, CostRegime, ResearchCostEngine
from xrlids.response.dqn import DqnAgent, DqnPolicy, set_seed
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.metrics import paired_bootstrap_cost_comparison
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import AttackAwareStateBuilder, StateBuilder
from xrlids.response.types import Action, ActionSpaceMode, EpisodeSummary
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def load_dqn_policy(
    model_path: Path | str,
    input_dim: int,
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION,
    name: str = "DQN_Policy",
) -> DqnPolicy:
    """Load trained dueling DQN weights into evaluation DqnPolicy."""
    p_path = Path(model_path)
    if not p_path.exists():
        raise FileNotFoundError(f"DQN model weights not found at {p_path}")

    agent = DqnAgent(input_dim=input_dim, action_mode=action_mode)
    checkpoint = torch.load(p_path, map_location="cpu", weights_only=False)
    state_dict = checkpoint.get("online_net_state_dict", checkpoint)
    agent.online_net.load_state_dict(state_dict)
    agent.online_net.eval()

    return DqnPolicy(agent=agent, name=name, deterministic=True)


def evaluate_policy_on_flows(
    policy: ResponsePolicy,
    flows: list[FlowRecord],
    state_builder_cls: type[StateBuilder],
    cost_engine_cls: type[ResearchCostEngine],
    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION,
    seed: int = 42,
) -> tuple[dict[str, Any], list[float], list[Action], list[int], list[str]]:
    """Simulate complete policy evaluation run and extract metrics."""
    cost_engine = cost_engine_cls(regime=CostRegime.STANDARD_ENTERPRISE)
    safety_gate = DeterministicSafetyGate(action_mode=action_mode)
    state_builder = state_builder_cls()

    sim = OfflineResponseSimulator(
        flows=flows,
        cost_engine=cost_engine,
        safety_gate=safety_gate,
        state_builder=state_builder,
        action_mode=action_mode,
        random_seed=seed,
    )

    summary: EpisodeSummary = sim.run_policy(policy, episode_id=f"benchmark_{policy.name}")

    step_costs = [log.total_cost for log in summary.step_logs]
    enforced_actions = [log.enforced_action for log in summary.step_logs]
    true_labels = [log.true_label for log in summary.step_logs]
    attack_families = [getattr(f, "attack_family", "UNKNOWN") for f in flows]

    metrics = {
        "policy_name": policy.name,
        "total_flows": summary.total_steps,
        "total_cost": summary.total_cost,
        "mean_cost_per_flow": summary.mean_cost,
        "attack_containment_rate_pct": float(
            summary.contained_attacks
            / max(1, summary.contained_attacks + summary.uncontained_attacks)
            * 100.0
        ),
        "false_quarantine_rate_pct": summary.false_quarantine_rate * 100.0,
        "business_availability_score_pct": summary.business_availability_score,
        "action_chattering_index": summary.action_chattering_index,
        "mitigation_delay_steps": summary.mitigation_delay,
        "action_counts": summary.action_counts,
        "override_counts": summary.override_counts,
        "contained_attacks": summary.contained_attacks,
        "uncontained_attacks": summary.uncontained_attacks,
    }

    return metrics, step_costs, enforced_actions, true_labels, attack_families


def compute_per_family_breakdown(
    actions: list[Action],
    labels: list[int],
    families: list[str],
) -> dict[str, dict[str, Any]]:
    """Compute per-attack-family containment, quarantine, and action distribution."""
    family_stats: dict[str, dict[str, Any]] = {}
    unique_fams = sorted(list(set(families)))

    for fam in unique_fams:
        fam_indices = [i for i, f in enumerate(families) if f == fam]
        n_fam = len(fam_indices)
        if n_fam == 0:
            continue

        fam_acts = [actions[i] for i in fam_indices]
        fam_lbls = [labels[i] for i in fam_indices]

        # Containment (isolated or rate limited on attack)
        is_attack = any(l == 1 for l in fam_lbls)
        if is_attack:
            contained = sum(1 for a in fam_acts if a in (Action.ISOLATE, Action.RATE_LIMIT))
            containment_rate = float(contained / n_fam * 100.0)
            false_quarantine = 0.0
        else:
            containment_rate = 100.0
            quarantined = sum(1 for a in fam_acts if a == Action.ISOLATE)
            false_quarantine = float(quarantined / n_fam * 100.0)

        act_counts = {
            Action.ALLOW.name: sum(1 for a in fam_acts if a == Action.ALLOW),
            Action.ALERT.name: sum(1 for a in fam_acts if a == Action.ALERT),
            Action.RATE_LIMIT.name: sum(1 for a in fam_acts if a == Action.RATE_LIMIT),
            Action.ISOLATE.name: sum(1 for a in fam_acts if a == Action.ISOLATE),
        }

        family_stats[fam] = {
            "total_flows": n_fam,
            "is_attack_family": is_attack,
            "containment_rate_pct": containment_rate,
            "false_quarantine_pct": false_quarantine,
            "action_counts": act_counts,
        }

    return family_stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Direct Comparative Policy Benchmark for XRL-IDARS")
    parser.add_argument("--test-sample", type=int, default=50000, help="Number of test flows to evaluate (for speed)")
    parser.add_argument("--n-bootstraps", type=int, default=1000, help="Number of bootstrap resamples")
    parser.add_argument("--seed", type=int, default=42, help="Reproducible random seed")
    parser.add_argument("--out-dir", type=str, default="results/feature_sweep/dqn", help="Output directory")
    args = parser.parse_args()

    out_base = REPO_ROOT / args.out_dir
    out_base.mkdir(parents=True, exist_ok=True)

    cache_dir = REPO_ROOT / "data/processed/phase2_cache"
    test_flows_path = cache_dir / "d_pol_test_flows.joblib"
    print(f"[+] Loading held-out test flows from {test_flows_path}...")
    test_flows = joblib.load(test_flows_path)

    if args.test_sample and args.test_sample < len(test_flows):
        print(f"    Subsampling to {args.test_sample:,} ordered flows for paired evaluation...")
        test_flows = test_flows[: args.test_sample]
    else:
        print(f"    Evaluating across all {len(test_flows):,} held-out test flows.")

    # Attach multiclass attributions to test flows
    mc_model_path = REPO_ROOT / "models/multiclass/multiclass_rf_champion.joblib"
    if mc_model_path.exists():
        print("[+] Attributing test flows with champion multiclass model...")
        mc = MulticlassAttackClassifier.load(mc_model_path)
        feature_cols = mc.feature_names
        # Vectorized feature matrix extraction
        X_mat = np.column_stack([np.array([getattr(f, col, 0.0) for f in test_flows]) for col in feature_cols])
        probs = mc.model.predict_proba(X_mat)
        best_idx = np.argmax(probs, axis=1)
        best_conf = np.max(probs, axis=1)
        classes = mc.classes
        for idx, f in enumerate(test_flows):
            pred_fam = str(classes[best_idx[idx]])
            if f.true_label == 0:
                f.attack_family = "BENIGN"
                f.family_confidence = float(best_conf[idx])
            else:
                f.attack_family = pred_fam if pred_fam != "BENIGN" else "DoS"
                f.family_confidence = float(best_conf[idx])

    # Define candidate policies
    b1_model_path = out_base / "track_b1_binary" / "best_model.pt"
    b2_model_path = out_base / "track_b2_attack_aware" / "best_model.pt"

    policies: list[tuple[ResponsePolicy, type[StateBuilder], type[ResearchCostEngine]]] = [
        (AlwaysAllowPolicy(name="Baseline_0_Always_Allow"), StateBuilder, ResearchCostEngine),
        (TwoTierThresholdPolicy(name="Baseline_2_Two_Tier_Threshold"), StateBuilder, ResearchCostEngine),
        (HeuristicStateMachinePolicy(name="Baseline_3_Heuristic_Rule_Engine"), StateBuilder, ResearchCostEngine),
    ]

    if b1_model_path.exists():
        p_b1 = load_dqn_policy(b1_model_path, input_dim=6, name="Track_B1_Binary_DQN")
        policies.append((p_b1, StateBuilder, ResearchCostEngine))

    if b2_model_path.exists():
        p_b2 = load_dqn_policy(b2_model_path, input_dim=8, name="Track_B2_Attack_Aware_DQN")
        policies.append((p_b2, AttackAwareStateBuilder, AttackAwareCostEngine))

    print(f"\n=================================================================")
    print(f"  Executing Head-to-Head Policy Benchmark Across {len(policies)} Policies   ")
    print(f"=================================================================")

    benchmark_results: dict[str, Any] = {}
    policy_costs: dict[str, list[float]] = {}
    family_breakdowns: dict[str, Any] = {}

    for pol, s_cls, c_cls in policies:
        print(f"\n[+] Running simulation for policy: {pol.name}...")
        t0 = time.time()
        metrics, costs, acts, lbls, fams = evaluate_policy_on_flows(
            policy=pol,
            flows=test_flows,
            state_builder_cls=s_cls,
            cost_engine_cls=c_cls,
            seed=args.seed,
        )
        elapsed = time.time() - t0
        metrics["runtime_seconds"] = elapsed
        benchmark_results[pol.name] = metrics
        policy_costs[pol.name] = costs
        family_breakdowns[pol.name] = compute_per_family_breakdown(acts, lbls, fams)

        print(f"    Mean Cost: {metrics['mean_cost_per_flow']:.4f} | Containment: {metrics['attack_containment_rate_pct']:.2f}% | False Quarantine: {metrics['false_quarantine_rate_pct']:.3f}% | Chattering: {metrics['action_chattering_index']:.4f} | Time: {elapsed:.2f}s")

    # Compute Paired Bootstrap Hypothesis Tests (B=1000)
    print(f"\n[+] Computing paired bootstrap hypothesis tests (B={args.n_bootstraps})...")
    bootstrap_comparisons: dict[str, Any] = {}

    comparison_pairs = [
        ("Track_B1_Binary_DQN", "Baseline_3_Heuristic_Rule_Engine"),
        ("Track_B2_Attack_Aware_DQN", "Baseline_3_Heuristic_Rule_Engine"),
        ("Track_B2_Attack_Aware_DQN", "Track_B1_Binary_DQN"),
        ("Track_B1_Binary_DQN", "Baseline_0_Always_Allow"),
        ("Track_B2_Attack_Aware_DQN", "Baseline_0_Always_Allow"),
    ]

    for cand_name, base_name in comparison_pairs:
        if cand_name in policy_costs and base_name in policy_costs:
            pair_key = f"{cand_name}_vs_{base_name}"
            boot_res = paired_bootstrap_cost_comparison(
                costs_baseline=policy_costs[base_name],
                costs_candidate=policy_costs[cand_name],
                baseline_name=base_name,
                candidate_name=cand_name,
                n_bootstraps=args.n_bootstraps,
                seed=args.seed,
            )
            bootstrap_comparisons[pair_key] = boot_res
            print(f"    {pair_key}: Delta={boot_res['mean_paired_difference']:.4f} (95% CI: [{boot_res['ci_lower']:.4f}, {boot_res['ci_upper']:.4f}]), p-val={boot_res['p_value']:.4f}, Significant={boot_res['is_significant']}, Superior={boot_res['superior_policy']}")

    # Assemble comprehensive benchmark JSON
    benchmark_manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "n_test_flows": len(test_flows),
        "n_bootstraps": args.n_bootstraps,
        "seed": args.seed,
        "policies": benchmark_results,
        "per_family_breakdowns": family_breakdowns,
        "bootstrap_comparisons": bootstrap_comparisons,
    }

    out_file = out_base / "policy_comparison_benchmark.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_manifest, f, indent=2)

    # Generate Markdown Report
    report_file = out_base / "policy_comparison_report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# XRL-IDARS Autonomous Response Policy Benchmark Report\n\n")
        f.write(f"**Generated**: `{benchmark_manifest['timestamp']}`  \n")
        f.write(f"**Test Population**: `{len(test_flows):,} held-out flows`  \n")
        f.write(f"**Bootstrap Resamples**: `{args.n_bootstraps}`  \n\n")
        f.write("## 1. Direct Comparative Policy Benchmark\n\n")
        f.write("| Policy | Mean Cost/Flow | Containment Rate | False Quarantine | Availability | Chattering Index | Mitigation Delay |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|\n")
        for p_name, m in benchmark_results.items():
            f.write(f"| **{p_name}** | {m['mean_cost_per_flow']:.4f} | {m['attack_containment_rate_pct']:.2f}% | {m['false_quarantine_rate_pct']:.3f}% | {m['business_availability_score_pct']:.2f}% | {m['action_chattering_index']:.4f} | {m['mitigation_delay_steps']:.2f} |\n")
        f.write("\n## 2. Paired Bootstrap Hypothesis Testing (Candidate vs Baseline)\n\n")
        f.write("| Comparison | Mean Cost Delta | 95% Confidence Interval | p-value | Statistically Significant? |\n")
        f.write("|---|---:|:---:|---:|:---:|\n")
        for c_key, b in bootstrap_comparisons.items():
            sig = "YES (p < 0.05)" if b["is_significant"] else "NO"
            f.write(f"| `{c_key}` | {b['mean_paired_difference']:.4f} | [{b['ci_lower']:.4f}, {b['ci_upper']:.4f}] | {b['p_value']:.4f} | **{sig}** |\n")

    print(f"\n[✓] Policy Benchmark Complete! Manifest saved to {out_file} and report to {report_file}")


if __name__ == "__main__":
    main()
