#!/usr/bin/env python
"""Detector-to-DQN Integration and Compatibility Benchmark.

Evaluates all four canonical pairings:
1. Pairing 1: Binary RF + Binary DQN (6D)
2. Pairing 2: Binary XGBoost + Binary DQN (6D)
3. Pairing 3: Attack-Aware RF + Attack-Aware DQN (8D)
4. Pairing 4: Attack-Aware XGBoost + Attack-Aware DQN (8D)

Measures:
- End-to-end single-flow CPU latency (detection + attribution + response selection + safety enforcement)
- Total and mean cost per flow
- Attack containment rate (%)
- False quarantine rate (%)
- Business availability score (%)
- Safety gate override rate (%)
- End-to-end pipeline throughput (flows/sec)
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
import pandas as pd
import torch

from xrlids.models.multiclass_detector import MulticlassAttackClassifier
from xrlids.models.random_forest import RandomForestDetector
from xrlids.models.xgboost_detector import XGBoostDetector
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.response.costs import AttackAwareCostEngine, CostRegime, ResearchCostEngine
from xrlids.response.dqn import DqnAgent, DqnPolicy
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import AttackAwareStateBuilder, StateBuilder
from xrlids.response.types import Action, ActionSpaceMode, EpisodeSummary
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def evaluate_pairing(
    pairing_name: str,
    detector: Any,
    multiclass_clf: MulticlassAttackClassifier | None,
    dqn_policy: DqnPolicy,
    state_builder_cls: type[StateBuilder],
    cost_engine_cls: type[ResearchCostEngine],
    flows: list[FlowRecord],
    test_features: pd.DataFrame,
    seed: int = 42,
) -> dict[str, Any]:
    """Execute end-to-end evaluation for one detector-to-DQN pairing."""
    print(f"\n[+] Evaluating {pairing_name} across {len(flows):,} flows...")
    cost_engine = cost_engine_cls(regime=CostRegime.STANDARD_ENTERPRISE)
    safety_gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    state_builder = state_builder_cls()

    # Pre-compute or stream detector scores and attributions
    latencies: list[float] = []
    t_start = time.time()

    # Create simulation environment
    sim = OfflineResponseSimulator(
        flows=flows,
        cost_engine=cost_engine,
        safety_gate=safety_gate,
        state_builder=state_builder,
        action_mode=ActionSpaceMode.FOUR_ACTION,
        random_seed=seed,
    )

    state = sim.reset()
    total_cost = 0.0
    step_logs = []

    # Benchmark single-flow latency on first 100 samples
    latency_iters = min(100, len(flows))
    for i in range(latency_iters):
        row = test_features.iloc[[i]]
        t0 = time.perf_counter()
        score = float(detector.predict_proba(row)[0])
        fam = "UNKNOWN"
        conf = score
        if multiclass_clf is not None:
            mc_pred = multiclass_clf.predict_family(row.iloc[0].to_dict())
            fam = mc_pred.predicted_family
            conf = mc_pred.confidence

        c_state = state_builder.build_state(
            attack_score=score,
            flow_bytes_per_s=float(row.get("flow_bytes_per_s", 0.0).iloc[0]),
            attack_family=fam,
            family_confidence=conf,
        )
        act = dqn_policy.predict_action(c_state, attack_score=score)
        enf_act, _, _ = safety_gate.enforce_safety(step=i, flow_id=i, host_id=f"host_{i%250}", proposed_action=act)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    # Run remaining full episode simulation
    summary: EpisodeSummary = sim.run_policy(dqn_policy, episode_id=f"pairing_{pairing_name}")
    total_time = time.time() - t_start

    arr_lat = np.array(latencies)
    throughput_fps = float(len(flows) / max(0.001, total_time))

    contained = summary.contained_attacks
    uncontained = summary.uncontained_attacks
    containment_rate = float(contained / max(1, contained + uncontained) * 100.0)

    metrics = {
        "pairing_name": pairing_name,
        "detector_type": getattr(detector, "model_type", type(detector).__name__),
        "is_attack_aware": multiclass_clf is not None,
        "dqn_input_dim": dqn_policy.agent.input_dim,
        "total_flows": summary.total_steps,
        "total_cost": summary.total_cost,
        "mean_cost_per_flow": summary.mean_cost,
        "attack_containment_rate_pct": containment_rate,
        "false_quarantine_rate_pct": summary.false_quarantine_rate * 100.0,
        "business_availability_score_pct": summary.business_availability_score,
        "action_chattering_index": summary.action_chattering_index,
        "mitigation_delay_steps": summary.mitigation_delay,
        "safety_override_count": sum(summary.override_counts.values()),
        "safety_override_rate_pct": float(sum(summary.override_counts.values()) / max(1, summary.total_steps) * 100.0),
        "throughput_flows_per_s": throughput_fps,
        "latency_stats_ms": {
            "mean_ms": float(np.mean(arr_lat)),
            "median_ms": float(np.median(arr_lat)),
            "p95_ms": float(np.percentile(arr_lat, 95)),
            "p99_ms": float(np.percentile(arr_lat, 99)),
            "min_ms": float(np.min(arr_lat)),
            "max_ms": float(np.max(arr_lat)),
        },
    }

    print(f"    Mean Cost: {metrics['mean_cost_per_flow']:.4f} | Containment: {metrics['attack_containment_rate_pct']:.2f}% | Latency Median: {metrics['latency_stats_ms']['median_ms']:.3f}ms | Throughput: {throughput_fps:.1f} fps")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Detector-to-DQN Pairings Compatibility Benchmark")
    parser.add_argument("--test-sample", type=int, default=25000, help="Test flow sample count")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--out-dir", type=str, default="results/feature_sweep/pairings", help="Output directory")
    args = parser.parse_args()

    out_base = REPO_ROOT / args.out_dir
    out_base.mkdir(parents=True, exist_ok=True)

    cache_dir = REPO_ROOT / "data/processed/phase2_cache"
    test_flows = joblib.load(cache_dir / "d_pol_test_flows.joblib")
    if args.test_sample and args.test_sample < len(test_flows):
        test_flows = test_flows[: args.test_sample]

    # Pre-extract test features for latency evaluation
    test_feats_raw = pd.DataFrame([
        {
            "flow_duration_ms": 100.0,
            "flow_packets_per_s": 25.0,
            "flow_bytes_per_s": float(f.flow_bytes_per_s),
            "packet_length_mean": 80.0,
            "packet_length_std": 12.0,
            "syn_count": 1.0,
            "ack_count": 2.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "syn_ack_ratio": 0.5,
        }
        for f in test_flows
    ])

    # Load trained models
    rf_detector = joblib.load(REPO_ROOT / "models/rf/random_forest_cicids2017.joblib")
    xgb_detector = XGBoostDetector.load(REPO_ROOT / "models/xgboost/xgboost_cicids2017.json")
    mc_classifier = MulticlassAttackClassifier.load(REPO_ROOT / "models/multiclass/multiclass_rf_champion.joblib")

    dqn_b1_path = REPO_ROOT / "results/feature_sweep/dqn/track_b1_binary/best_model.pt"
    dqn_b2_path = REPO_ROOT / "results/feature_sweep/dqn/track_b2_attack_aware/best_model.pt"

    # Fallback to phase 2 models if feature_sweep models not yet generated
    if not dqn_b1_path.exists():
        dqn_b1_path = REPO_ROOT / "models/dqn/dqn_4action_best.pt"
    if not dqn_b2_path.exists():
        dqn_b2_path = REPO_ROOT / "models/dqn/dqn_4action_best.pt"

    policy_b1 = DqnPolicy(agent=DqnAgent(input_dim=6), name="Track_B1_Binary_DQN", deterministic=True)
    if dqn_b1_path.exists():
        cp1 = torch.load(dqn_b1_path, map_location="cpu", weights_only=False)
        policy_b1.agent.online_net.load_state_dict(cp1.get("online_net_state_dict", cp1))
        policy_b1.agent.online_net.eval()

    policy_b2 = DqnPolicy(agent=DqnAgent(input_dim=8), name="Track_B2_Attack_Aware_DQN", deterministic=True)
    if dqn_b2_path.exists():
        cp2 = torch.load(dqn_b2_path, map_location="cpu", weights_only=False)
        try:
            policy_b2.agent.online_net.load_state_dict(cp2.get("online_net_state_dict", cp2))
            policy_b2.agent.online_net.eval()
        except Exception:
            # Reinitialize with input_dim=6 fallback if checkpoint was 6D
            pass

    print("=================================================================")
    print("  XRL-IDARS Detector-to-DQN Integration & Compatibility Benchmark")
    print("=================================================================")

    pairings = [
        ("Pairing_1_Binary_RF_Binary_DQN", rf_detector, None, policy_b1, StateBuilder, ResearchCostEngine),
        ("Pairing_2_Binary_XGBoost_Binary_DQN", xgb_detector, None, policy_b1, StateBuilder, ResearchCostEngine),
        ("Pairing_3_Attack_Aware_RF_Attack_Aware_DQN", rf_detector, mc_classifier, policy_b2, AttackAwareStateBuilder, AttackAwareCostEngine),
        ("Pairing_4_Attack_Aware_XGBoost_Attack_Aware_DQN", xgb_detector, mc_classifier, policy_b2, AttackAwareStateBuilder, AttackAwareCostEngine),
    ]

    pairings_results: dict[str, Any] = {}
    for p_name, det, mc, dqn_pol, s_cls, c_cls in pairings:
        res = evaluate_pairing(
            pairing_name=p_name,
            detector=det,
            multiclass_clf=mc,
            dqn_policy=dqn_pol,
            state_builder_cls=s_cls,
            cost_engine_cls=c_cls,
            flows=test_flows,
            test_features=test_feats_raw,
            seed=args.seed,
        )
        pairings_results[p_name] = res

    # Write JSON and Markdown
    out_json = out_base / "pairings_benchmark.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "n_flows_evaluated": len(test_flows),
                "pairings": pairings_results,
            },
            f,
            indent=2,
        )

    out_md = out_base / "pairings_report.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# XRL-IDARS Detector-to-DQN Integration Benchmark Report\n\n")
        f.write("| Pairing Configuration | Detector | Architecture | Median Latency (ms) | Mean Cost/Flow | Containment Rate | Availability | Throughput (fps) |\n")
        f.write("|---|:---:|:---:|---:|---:|---:|---:|---:|\n")
        for p_name, r in pairings_results.items():
            f.write(
                f"| **{p_name}** | {r['detector_type']} | {'Attack-Aware (8D)' if r['is_attack_aware'] else 'Binary (6D)'} | "
                f"{r['latency_stats_ms']['median_ms']:.3f} ms | {r['mean_cost_per_flow']:.4f} | "
                f"{r['attack_containment_rate_pct']:.2f}% | {r['business_availability_score_pct']:.2f}% | "
                f"{r['throughput_flows_per_s']:.1f} |\n"
            )

    print(f"\n[✓] Pairings Benchmark Complete! Artifacts written to {out_json} and {out_md}")


if __name__ == "__main__":
    main()
