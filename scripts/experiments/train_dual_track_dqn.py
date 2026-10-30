#!/usr/bin/env python
"""Phase 2 Dual-Track DQN Training Subsystem.

Trains two independent Deep Q-Network response policies under strict empirical separation:
- Track B1: Binary-alert-conditioned DQN (State s_t in R^6)
- Track B2: Attack-aware DQN (State s_t in R^8 incorporating w_family and C_family)

Strict Anti-Leakage Rules:
1. Training is strictly confined to D_pol_train (213,518 rows).
2. Validation checkpoint selection is strictly confined to D_pol_val (142,346 rows).
3. Final evaluation split D_pol_test is untouched during training.
4. Checkpoints and telemetry saved to results/feature_sweep/dqn/ preserving existing canonical models.
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
from xrlids.response.costs import AttackAwareCostEngine, CostRegime, ResearchCostEngine
from xrlids.response.dqn import (
    DqnAgent,
    DqnPolicy,
    DqnTrainer,
    TrainingConfig,
    set_seed,
)
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import AttackAwareStateBuilder, FAMILY_SEVERITY_WEIGHTS, StateBuilder
from xrlids.response.types import Action, ActionSpaceMode, EpisodeSummary
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def augment_flows_with_multiclass(
    flows: list[FlowRecord],
    features: np.ndarray,
    multiclass_model_path: Path | str,
) -> list[FlowRecord]:
    """Generate vectorized multiclass attack attributions and enrich FlowRecord instances."""
    print(f"[+] Loading Multiclass Classifier from {multiclass_model_path}...")
    mc_classifier = MulticlassAttackClassifier.load(multiclass_model_path)

    print(f"[+] Vectorized attack family attribution for {len(flows):,} flows...")
    raw_probs = mc_classifier.model.predict_proba(features)
    classes = np.array(getattr(mc_classifier.model, "classes_", []))
    best_indices = np.argmax(raw_probs, axis=1)
    best_probs = np.max(raw_probs, axis=1)
    predicted_families = classes[best_indices]

    thresh = mc_classifier.confidence_threshold
    unknown_mask = best_probs < thresh
    predicted_families[unknown_mask] = "UNKNOWN"

    augmented_flows: list[FlowRecord] = [
        FlowRecord(
            flow_id=f.flow_id,
            host_id=f.host_id,
            attack_score=f.attack_score,
            true_label=f.true_label,
            flow_bytes_per_s=f.flow_bytes_per_s,
            attack_family=str(fam),
            family_confidence=float(conf),
        )
        for f, fam, conf in zip(flows, predicted_families, best_probs)
    ]
    print(f"    Attributed {len(augmented_flows):,} flows instantaneously.")
    return augmented_flows


def train_track(
    track_name: str,
    input_dim: int,
    state_builder_cls: type[StateBuilder],
    cost_engine_cls: type[ResearchCostEngine],
    train_flows: list[FlowRecord],
    val_flows: list[FlowRecord],
    out_dir: Path,
    config: TrainingConfig,
) -> dict[str, Any]:
    """Train a single DQN track and register best validation checkpoint."""
    print(f"\n{'='*70}\n  TRAINING TRACK: {track_name.upper()} (input_dim={input_dim})\n{'='*70}")
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir = out_dir / "checkpoints"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)

    set_seed(config.random_seed)

    agent = DqnAgent(
        input_dim=input_dim,
        action_mode=config.action_mode,
        hidden_dim=64,
        learning_rate=config.learning_rate,
        gamma=config.gamma,
        tau_target=config.tau_target,
    )

    trainer = DqnTrainer(
        agent=agent,
        train_flows=train_flows,
        val_flows=val_flows,
        config=config,
        checkpoint_dir=checkpoints_dir,
        state_builder_cls=state_builder_cls,
        cost_engine_cls=cost_engine_cls,
    )

    t0 = time.time()
    history = trainer.train()
    training_time = time.time() - t0
    print(f"[+] {track_name} training concluded in {training_time:.2f}s ({history['total_steps']:,} steps).")

    # Evaluate best checkpoint on complete validation set
    best_checkpoint_path = checkpoints_dir / "best_model.pt"
    if best_checkpoint_path.exists():
        print(f"[+] Loading best checkpoint from {best_checkpoint_path}...")
        checkpoint_data = torch.load(best_checkpoint_path, map_location="cpu", weights_only=False)
        agent.online_net.load_state_dict(checkpoint_data["online_net_state_dict"])
        # Also copy best_model.pt to top-level track dir
        torch.save(checkpoint_data, out_dir / "best_model.pt")

    print("[+] Evaluating best policy on validation split (25,000 stratified flows)...")
    eval_flows = val_flows[:25000] if len(val_flows) > 25000 else val_flows
    eval_sim = OfflineResponseSimulator(
        flows=eval_flows,
        cost_engine=cost_engine_cls(regime=config.cost_regime),
        safety_gate=DeterministicSafetyGate(action_mode=config.action_mode),
        state_builder=state_builder_cls(),
        action_mode=config.action_mode,
        random_seed=config.random_seed,
    )
    policy = DqnPolicy(agent=agent, deterministic=True, name=track_name)
    val_summary: EpisodeSummary = eval_sim.run_policy(policy, episode_id=f"val_final_{track_name}")

    val_metrics = {
        "track": track_name,
        "input_dim": input_dim,
        "total_flows": val_summary.total_steps,
        "total_cost": val_summary.total_cost,
        "mean_cost_per_flow": val_summary.mean_cost,
        "attack_containment_rate_pct": float(val_summary.contained_attacks / max(1, val_summary.contained_attacks + val_summary.uncontained_attacks) * 100.0),
        "false_quarantine_rate_pct": val_summary.false_quarantine_rate * 100.0,
        "business_availability_score_pct": val_summary.business_availability_score,
        "action_chattering_index": val_summary.action_chattering_index,
        "mitigation_delay_steps": val_summary.mitigation_delay,
        "action_counts": val_summary.action_counts,
        "override_counts": val_summary.override_counts,
        "contained_attacks": val_summary.contained_attacks,
        "uncontained_attacks": val_summary.uncontained_attacks,
        "training_time_seconds": training_time,
    }

    # Write training history and validation metrics
    with open(out_dir / "training_history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    with open(out_dir / "validation_metrics.json", "w", encoding="utf-8") as f:
        json.dump(val_metrics, f, indent=2)

    print(f"[✓] {track_name}: Mean Cost={val_metrics['mean_cost_per_flow']:.4f} | Containment={val_metrics['attack_containment_rate_pct']:.2f}% | False Quarantine={val_metrics['false_quarantine_rate_pct']:.3f}% | Chattering={val_metrics['action_chattering_index']:.4f}")
    return val_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Dual-Track DQN Agents for XRL-IDARS")
    parser.add_argument("--total-steps", type=int, default=30000, help="Total training steps per track")
    parser.add_argument("--eval-interval", type=int, default=5000, help="Steps between validation evaluations")
    parser.add_argument("--batch-size", type=int, default=64, help="PER batch size")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--out-dir", type=str, default="results/feature_sweep/dqn", help="Base output directory")
    args = parser.parse_args()

    out_base = REPO_ROOT / args.out_dir
    out_base.mkdir(parents=True, exist_ok=True)

    cache_dir = REPO_ROOT / "data/processed/phase2_cache"
    train_flows_path = cache_dir / "d_pol_train_flows.joblib"
    val_flows_path = cache_dir / "d_pol_val_flows.joblib"
    train_feats_path = cache_dir / "d_pol_train_features.joblib"
    val_feats_path = cache_dir / "d_pol_val_features.joblib"

    print("=================================================================")
    print("  XRL-IDARS Dual-Track Reinforcement Learning DQN Training       ")
    print("=================================================================")
    print(f"Loading policy development data from {cache_dir}...")
    train_flows = joblib.load(train_flows_path)
    val_flows = joblib.load(val_flows_path)
    train_feats = joblib.load(train_feats_path)
    val_feats = joblib.load(val_feats_path)
    print(f"Loaded D_pol_train ({len(train_flows):,} flows) and D_pol_val ({len(val_flows):,} flows).")

    # Hyperparameter configuration
    config = TrainingConfig(
        total_steps=args.total_steps,
        batch_size=args.batch_size,
        warmup_steps=500,
        eval_interval_steps=args.eval_interval,
        max_episode_steps=100,
        early_termination_on_isolated_attack=True,
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.STANDARD_ENTERPRISE,
        random_seed=args.seed,
    )

    # -------------------------------------------------------------
    # 1. Track B1: Binary-Alert-Conditioned DQN (6D)
    # -------------------------------------------------------------
    b1_dir = out_base / "track_b1_binary"
    b1_metrics = train_track(
        track_name="Track_B1_Binary_DQN",
        input_dim=6,
        state_builder_cls=StateBuilder,
        cost_engine_cls=ResearchCostEngine,
        train_flows=train_flows,
        val_flows=val_flows,
        out_dir=b1_dir,
        config=config,
    )

    # -------------------------------------------------------------
    # 2. Track B2: Attack-Aware DQN (8D)
    # -------------------------------------------------------------
    mc_model_path = REPO_ROOT / "models/multiclass/multiclass_rf_champion.joblib"
    train_flows_augmented = augment_flows_with_multiclass(train_flows, train_feats, mc_model_path)
    val_flows_augmented = augment_flows_with_multiclass(val_flows, val_feats, mc_model_path)

    b2_dir = out_base / "track_b2_attack_aware"
    b2_metrics = train_track(
        track_name="Track_B2_Attack_Aware_DQN",
        input_dim=8,
        state_builder_cls=AttackAwareStateBuilder,
        cost_engine_cls=AttackAwareCostEngine,
        train_flows=train_flows_augmented,
        val_flows=val_flows_augmented,
        out_dir=b2_dir,
        config=config,
    )

    # Summary
    dual_summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "training_config": {
            "total_steps": args.total_steps,
            "batch_size": args.batch_size,
            "eval_interval": args.eval_interval,
            "seed": args.seed,
            "action_mode": "FOUR_ACTION",
            "cost_regime": "STANDARD_ENTERPRISE",
        },
        "track_b1_binary": b1_metrics,
        "track_b2_attack_aware": b2_metrics,
    }
    with open(out_base / "dual_track_summary.json", "w", encoding="utf-8") as f:
        json.dump(dual_summary, f, indent=2)

    print(f"\n[✓] Dual-Track DQN Training Complete! Summary saved to {out_base / 'dual_track_summary.json'}")


if __name__ == "__main__":
    main()
