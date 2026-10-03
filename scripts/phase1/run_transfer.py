#!/usr/bin/env python
"""Phase 1 Unified Cross-Dataset Transfer Runner (Task 4: Build Spec §§28, 30, 31, 38).

Executes reproducible, scientifically isolated cross-dataset transfer experiments:
1. Primary 10-Feature Transfers (R10):
   - CIC-IDS2017 -> CSE-CIC-IDS2018 (EXP-P1-TRANSFER-CIC-TO-CSE-R10-001)
   - CSE-CIC-IDS2018 -> CIC-IDS2017 (EXP-P1-TRANSFER-CSE-TO-CIC-R10-001)
2. Auxiliary 4-Feature Transfers (R4):
   - UNSW-NB15 -> CIC-IDS2017 (EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001)
   - UNSW-NB15 -> CSE-CIC-IDS2018 (EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001)
   - CIC-IDS2017 -> UNSW-NB15 (EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001)
   - CSE-CIC-IDS2018 -> UNSW-NB15 (EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001)

Scientific Isolation Protocol:
- Preprocessor is fit strictly on SOURCE training population.
- Detectors are trained strictly on SOURCE domain.
- Score fusion weight alpha is tuned strictly on SOURCE validation set.
- Target domain test split is evaluated strictly out-of-domain.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# Ensure src is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import joblib
import numpy as np
import pandas as pd
import yaml

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact
from xrlids.datasets.loading import dataset_availability, load_manifest
from xrlids.datasets.population import (
    DatasetPopulation,
    PopulationConfig,
    load_dataset_population,
)
from xrlids.evaluation.error_analysis import (
    analyze_model_disagreements,
    compute_per_family_metrics,
)
from xrlids.evaluation.metrics import evaluate
from xrlids.experiments.registry import (
    ExperimentRecord,
    load_yaml_config,
    write_experiment_record,
)
from xrlids.experiments.transfer import (
    R4_FEATURES,
    R10_FEATURES,
    compute_distribution_shift,
    generate_transfer_card,
)
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract
from xrlids.models.baselines import (
    DecisionTreeDetector,
    LogisticRegressionDetector,
    MajorityClassDetector,
)
from xrlids.models.fusion import align_scores, fuse_scores, tune_fusion_alpha
from xrlids.models.lstm import LSTMDetector, SequenceSet, build_sequences
from xrlids.models.random_forest import RandomForestDetector
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.splitting.splitter import SplitConfig, build_splits
from xrlids.utils.env import environment_fingerprint, git_commit
from xrlids.utils.hashing import feature_schema_hash
from xrlids.utils.logging_utils import get_logger
from xrlids.utils.profiler import ResourceProfiler
from xrlids.utils.seeding import set_global_seeds

logger = get_logger("run_transfer")

# Global dataset cache to avoid reloading massive CSV populations repeatedly
POPULATION_CACHE: dict[str, tuple[DatasetPopulation, Any]] = {}


def get_cached_split(
    dataset_key: str,
    feature_names: list[str],
    *,
    seed: int = 42,
) -> tuple[DatasetPopulation, Any]:
    """Load and cache multi-file population and canonical split."""
    cache_key = dataset_key
    if cache_key in POPULATION_CACHE:
        logger.info("Using cached population for %s", dataset_key)
        return POPULATION_CACHE[cache_key]

    load_features = R10_FEATURES if dataset_key in ("cicids2017", "cse_cic_ids2018") else R4_FEATURES
    logger.info("Loading population for %s (%d features)...", dataset_key, len(load_features))
    contract = load_label_contract()
    registry = load_feature_registry()

    pop_config = PopulationConfig(
        dataset=dataset_key,
        files="all",
        require_verified_checksums=True,
        require_schema_validated=True,
        duplicate_policy="deduplicate_features",
        duplicate_conflict_policy="reject_conflicts",
        seed=seed,
    )
    pop = load_dataset_population(
        pop_config,
        load_features,
        contract=contract,
        registry=registry,
    )

    split_config = SplitConfig(
        train=0.6,
        validation=0.2,
        test=0.2,
        seed=seed,
        methodology="stratified_random",
        rationale="Canonical transfer split with duplicate_policy=deduplicate_features",
        duplicate_policy="deduplicate_features",
    )
    split_res = build_splits(
        pop.features,
        pop.labels,
        list(pop.features.columns),
        split_config,
        dataset=dataset_key,
        provenance=pop.provenance,
        run_leakage_audit=True,
    )

    POPULATION_CACHE[cache_key] = (pop, split_res)
    return pop, split_res


def execute_transfer_direction(
    config_path: Path,
    *,
    seed: int = 42,
) -> dict[str, Any]:
    """Execute a single cross-dataset transfer experiment."""
    set_global_seeds(seed)
    cfg = load_yaml_config(config_path)

    exp_cfg = cfg.get("experiment", {})
    exp_id = exp_cfg.get("id")
    src_cfg = cfg.get("source", {})
    tgt_cfg = cfg.get("target", {})
    source_key = src_cfg.get("dataset")
    target_key = tgt_cfg.get("dataset")
    contract_name = src_cfg.get("contract", "R10")

    if contract_name in ("R10", "r10"):
        feature_names = list(R10_FEATURES)
    else:
        feature_names = list(R4_FEATURES)

    out_dir = Path(cfg.get("outputs", {}).get("results_dir", f"results/experiments/{exp_id}"))
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*80}")
    print(f"EXECUTING CROSS-DATASET TRANSFER: {exp_id}")
    print(f"Source: {source_key} -> Target: {target_key} ({contract_name}: {len(feature_names)} features)")
    print(f"Output Directory: {out_dir}")
    print(f"{'='*80}")

    profiler = ResourceProfiler(target_dir=out_dir)
    profiler.__enter__()
    start_time = time.time()

    # 1. Obtain Source Models and Preprocessor
    source_exp_id = src_cfg.get("experiment_id")
    source_exp_dir = Path(f"results/experiments/{source_exp_id}") if source_exp_id else None

    # Check if frozen source models exist
    has_frozen_source = (
        source_exp_dir is not None
        and (source_exp_dir / "preprocessor.joblib").exists()
        and (source_exp_dir / "random_forest.joblib").exists()
        and (source_exp_dir / "lstm.pt").exists()
    )

    if has_frozen_source:
        print(f"\n[1/5] Loading frozen source models from {source_exp_dir}...")
        preprocessor = joblib.load(source_exp_dir / "preprocessor.joblib")
        rf_model = joblib.load(source_exp_dir / "random_forest.joblib")
        lstm_model = LSTMDetector.load(source_exp_dir / "lstm.pt")
        dt_model = joblib.load(source_exp_dir / "decision_tree.joblib")
        lr_model = joblib.load(source_exp_dir / "logistic_regression.joblib")
        maj_model = joblib.load(source_exp_dir / "majority_class.joblib")

        with open(source_exp_dir / "experiment_record.json", encoding="utf-8") as f:
            src_rec = json.load(f)
        with open(source_exp_dir / "test_metrics.json", encoding="utf-8") as f:
            src_tm = json.load(f)

        src_ref_aligned = src_tm.get("aligned", {})
        src_models_dict = src_ref_aligned.get("models", src_ref_aligned)
        alpha_val = (
            cfg.get("models", {}).get("fusion", {}).get("frozen_alpha")
            or src_rec.get("models", {}).get("fusion", {}).get("params", {}).get("alpha")
            or src_rec.get("fusion", {}).get("alpha")
            or 0.5
        )
        frozen_alpha = float(alpha_val)
        print(f"       Loaded frozen preprocessor, 5 detectors, and frozen fusion alpha = {frozen_alpha:.2f}")

        # Also load source population for distribution shift analysis
        source_pop, source_split = get_cached_split(source_key, feature_names, seed=seed)
        X_source_train = source_split.splits["train"][feature_names]
        y_source_train = source_split.label_splits["train"]
    else:
        print(f"\n[1/5] Training 4-feature source models on {source_key} under strict isolation...")
        source_pop, source_split = get_cached_split(source_key, feature_names, seed=seed)
        X_source_train = source_split.splits["train"][feature_names]
        y_source_train = source_split.label_splits["train"]
        X_source_val = source_split.splits["validation"][feature_names]
        y_source_val = source_split.label_splits["validation"]
        X_source_test = source_split.splits["test"][feature_names]
        y_source_test = source_split.label_splits["test"]

        prov_src_train = source_split.provenance_splits.get("train", pd.DataFrame())
        prov_src_val = source_split.provenance_splits.get("validation", pd.DataFrame())
        prov_src_test = source_split.provenance_splits.get("test", pd.DataFrame())

        # Fit preprocessor on SOURCE TRAIN ONLY
        preprocessor = Preprocessor(features=feature_names, dataset=source_key)
        preprocessor.fit(X_source_train, train_labels=y_source_train)

        X_src_tr_s = preprocessor.transform(X_source_train)
        X_src_va_s = preprocessor.transform(X_source_val)
        X_src_te_s = preprocessor.transform(X_source_test)

        # Train baseline ladder
        maj_model = MajorityClassDetector().fit(X_src_tr_s, y_source_train)
        lr_model = LogisticRegressionDetector().fit(X_src_tr_s, y_source_train)
        dt_model = DecisionTreeDetector().fit(X_src_tr_s, y_source_train)

        # Train RF
        rf_cfg = cfg.get("models", {}).get("random_forest", {})
        rf_params = {
            "n_estimators": int(rf_cfg.get("n_estimators", 100)),
            "max_depth": int(rf_cfg.get("max_depth", 16)),
            "min_samples_leaf": int(rf_cfg.get("min_samples_leaf", 2)),
            "class_weight": rf_cfg.get("class_weight", "balanced_subsample"),
            "random_state": seed,
            "n_jobs": int(rf_cfg.get("n_jobs", 4)),
        }
        rf_model = RandomForestDetector(params=rf_params, feature_names=feature_names)
        rf_model.fit(X_src_tr_s, y_source_train)

        # Train LSTM
        lstm_cfg = cfg.get("models", {}).get("lstm", {})
        lstm_params = {
            "hidden_size": int(lstm_cfg.get("hidden_size", 32)),
            "num_layers": int(lstm_cfg.get("num_layers", 2)),
            "dropout": float(lstm_cfg.get("dropout", 0.2)),
            "learning_rate": float(lstm_cfg.get("learning_rate", 0.001)),
            "batch_size": int(lstm_cfg.get("batch_size", 2048)),
            "epochs": int(lstm_cfg.get("epochs", 5)),
            "patience": int(lstm_cfg.get("patience", 2)),
            "seed": seed,
        }
        train_sess = prov_src_train["source_file"] if "source_file" in prov_src_train.columns else None
        val_sess = prov_src_val["source_file"] if "source_file" in prov_src_val.columns else None
        test_sess = prov_src_test["source_file"] if "source_file" in prov_src_test.columns else None

        train_seqs = build_sequences(X_src_tr_s, y_source_train, split="train", seq_len=5, stride=1, label_rule="last", session_column=train_sess)
        val_seqs = build_sequences(X_src_va_s, y_source_val, split="validation", seq_len=5, stride=1, label_rule="last", session_column=val_sess)
        test_seqs = build_sequences(X_src_te_s, y_source_test, split="test", seq_len=5, stride=1, label_rule="last", session_column=test_sess)

        lstm_model = LSTMDetector(params=lstm_params, feature_names=feature_names, seq_len=5, seed=seed)
        lstm_model.fit(train_seqs, val_seqs)

        # Tune fusion alpha on SOURCE VALIDATION ONLY
        rf_val_s = pd.Series(rf_model.predict_proba(X_src_va_s), index=X_source_val.index)
        lstm_val_s = pd.Series(lstm_model.predict_proba(val_seqs), index=val_seqs.origins + 4)
        aligned_v_rf, aligned_v_lstm, _ = align_scores(rf_val_s, lstm_val_s, how="inner")
        y_val_aligned = pd.Series(y_source_val.to_numpy()[aligned_v_rf.index], index=aligned_v_rf.index)

        tune_res = tune_fusion_alpha(aligned_v_rf, aligned_v_lstm, y_val_aligned, metric="roc_auc")
        frozen_alpha = float(tune_res["best_alpha"])
        print(f"       Tuned source fusion alpha on validation: {frozen_alpha:.2f} (val ROC-AUC: {tune_res['best_metric_value']:.4f})")

        # Compute source reference metrics on SOURCE TEST SET
        rf_test_s = pd.Series(rf_model.predict_proba(X_src_te_s), index=X_source_test.index)
        lstm_test_s = pd.Series(lstm_model.predict_proba(test_seqs), index=test_seqs.origins + 4)
        aligned_t_rf, aligned_t_lstm, _ = align_scores(rf_test_s, lstm_test_s, how="inner")
        aligned_idx = aligned_t_rf.index
        y_test_aligned = pd.Series(y_source_test.to_numpy()[aligned_idx], index=aligned_idx)

        maj_s = pd.Series(maj_model.predict_proba(X_src_te_s), index=X_source_test.index)[aligned_idx]
        lr_s = pd.Series(lr_model.predict_proba(X_src_te_s), index=X_source_test.index)[aligned_idx]
        dt_s = pd.Series(dt_model.predict_proba(X_src_te_s), index=X_source_test.index)[aligned_idx]
        fus_s = pd.Series(fuse_scores(aligned_t_rf, aligned_t_lstm, alpha=frozen_alpha).scores, index=aligned_idx)

        src_ref_aligned = {
            "population_size": len(aligned_idx),
            "majority": evaluate(y_test_aligned, maj_s, threshold=0.5),
            "logistic_regression": evaluate(y_test_aligned, lr_s, threshold=0.5),
            "decision_tree": evaluate(y_test_aligned, dt_s, threshold=0.5),
            "rf": evaluate(y_test_aligned, aligned_t_rf, threshold=0.5),
            "lstm": evaluate(y_test_aligned, aligned_t_lstm, threshold=0.5),
            "fusion": evaluate(y_test_aligned, fus_s, threshold=0.5),
        }
        src_models_dict = src_ref_aligned
        print(f"       Source in-domain test F1: RF={src_ref_aligned['rf']['f1']:.4f}, LSTM={src_ref_aligned['lstm']['f1']:.4f}, Fusion={src_ref_aligned['fusion']['f1']:.4f}")

    # 2. Load Target Population and Held-Out Test Split
    print(f"\n[2/5] Loading target dataset '{target_key}' test split...")
    target_pop, target_split = get_cached_split(target_key, feature_names, seed=seed)

    X_target_test = target_split.splits["test"][feature_names]
    y_target_test = target_split.label_splits["test"]
    prov_target_test = target_split.provenance_splits.get("test", pd.DataFrame())

    print(f"       Target test population: {len(X_target_test):,} rows across {len(target_pop.files)} files.")

    # 3. Transform Target Features Using FROZEN SOURCE Preprocessor
    print("\n[3/5] Applying frozen SOURCE preprocessor to target test features...")
    # Strict isolation: transform target using source scaler parameters; never fit on target
    X_target_test_scaled = preprocessor.transform(X_target_test)

    # 4. Run Model Inference on Target Domain
    print("\n[4/5] Evaluating detector ladder on target domain test data...")
    t0 = time.time()
    maj_target_scores = pd.Series(maj_model.predict_proba(X_target_test_scaled), index=X_target_test.index)
    lr_target_scores = pd.Series(lr_model.predict_proba(X_target_test_scaled), index=X_target_test.index)
    dt_target_scores = pd.Series(dt_model.predict_proba(X_target_test_scaled), index=X_target_test.index)
    rf_target_scores = pd.Series(rf_model.predict_proba(X_target_test_scaled), index=X_target_test.index)
    print(f"       Tabular detectors inference completed in {time.time() - t0:.2f}s")

    # Sequence inference for LSTM
    t0 = time.time()
    target_session = prov_target_test["source_file"] if "source_file" in prov_target_test.columns else None
    target_test_seqs = build_sequences(
        X_target_test_scaled,
        y_target_test,
        split="test",
        seq_len=5,
        stride=1,
        label_rule="last",
        session_column=target_session,
    )
    lstm_target_raw_scores = lstm_model.predict_proba(target_test_seqs, batch_size=4096)
    lstm_target_scores = pd.Series(lstm_target_raw_scores, index=target_test_seqs.origins + 4, name="lstm_score")
    print(f"       LSTM inference ({len(target_test_seqs):,} sequences) completed in {time.time() - t0:.2f}s")

    # Aligned population on target domain
    aligned_tgt_rf, aligned_tgt_lstm, _ = align_scores(rf_target_scores, lstm_target_scores, how="inner")
    target_aligned_idx = aligned_tgt_rf.index
    y_target_aligned = pd.Series(y_target_test.to_numpy()[target_aligned_idx], index=target_aligned_idx)

    maj_target_aligned = maj_target_scores[target_aligned_idx]
    lr_target_aligned = lr_target_scores[target_aligned_idx]
    dt_target_aligned = dt_target_scores[target_aligned_idx]

    # Fusion on target domain using FROZEN SOURCE ALPHA
    fusion_target_res = fuse_scores(aligned_tgt_rf, aligned_tgt_lstm, alpha=frozen_alpha, how="strict")
    fusion_target_scores = pd.Series(fusion_target_res.scores, index=target_aligned_idx, name="fusion_score")

    # Evaluate metrics on target domain aligned population
    transfer_metrics: dict[str, Any] = {
        "aligned": {
            "population_size": len(target_aligned_idx),
            "majority": evaluate(y_target_aligned, maj_target_aligned, threshold=0.5),
            "logistic_regression": evaluate(y_target_aligned, lr_target_aligned, threshold=0.5),
            "decision_tree": evaluate(y_target_aligned, dt_target_aligned, threshold=0.5),
            "rf": evaluate(y_target_aligned, aligned_tgt_rf, threshold=0.5),
            "lstm": evaluate(y_target_aligned, aligned_tgt_lstm, threshold=0.5),
            "fusion": evaluate(y_target_aligned, fusion_target_scores, threshold=0.5),
        }
    }

    # 5. Calculate Transfer Degradation Against Source Reference
    degradation_table: list[dict[str, Any]] = []
    models_to_compare = [
        ("majority", "Majority"),
        ("logistic_regression", "Logistic Regression"),
        ("decision_tree", "Decision Tree"),
        ("rf", "Random Forest"),
        ("lstm", "Supervised LSTM"),
        ("fusion", "RF + LSTM Fusion"),
    ]

    for m_key, m_name in models_to_compare:
        src_m = src_models_dict.get(m_key, {})
        if not src_m and m_key == "rf":
            src_m = src_models_dict.get("random_forest", {})
        if not src_m and m_key == "random_forest":
            src_m = src_models_dict.get("rf", {})

        tgt_m = transfer_metrics["aligned"].get(m_key, {})
        if not tgt_m and m_key == "rf":
            tgt_m = transfer_metrics["aligned"].get("random_forest", {})

        src_f1 = float(src_m.get("f1", 0.0) or 0.0)
        tgt_f1 = float(tgt_m.get("f1", 0.0) or 0.0)
        d_f1 = float(tgt_f1 - src_f1)

        src_fpr = float(src_m.get("fpr", 0.0) or 0.0)
        tgt_fpr = float(tgt_m.get("fpr", 0.0) or 0.0)
        d_fpr = float(tgt_fpr - src_fpr)

        src_acc = float(src_m.get("accuracy", 0.0) or 0.0)
        tgt_acc = float(tgt_m.get("accuracy", 0.0) or 0.0)
        d_acc = float(tgt_acc - src_acc)

        src_auc = float(src_m.get("roc_auc", 0.0) or 0.0)
        tgt_auc = float(tgt_m.get("roc_auc", 0.0) or 0.0)
        d_auc = float(tgt_auc - src_auc)

        degradation_table.append({
            "model": m_key,
            "model_name": m_name,
            "source_f1": src_f1,
            "transfer_f1": tgt_f1,
            "delta_f1": d_f1,
            "source_fpr": src_fpr,
            "transfer_fpr": tgt_fpr,
            "delta_fpr": d_fpr,
            "source_accuracy": src_acc,
            "transfer_accuracy": tgt_acc,
            "delta_accuracy": d_acc,
            "source_roc_auc": src_auc,
            "transfer_roc_auc": tgt_auc,
            "delta_roc_auc": d_auc,
            "transfer_precision": float(tgt_m.get("precision", 0.0) or 0.0),
            "transfer_recall": float(tgt_m.get("recall", 0.0) or 0.0),
            "transfer_pr_auc": float(tgt_m.get("pr_auc", 0.0) or 0.0),
        })

    # 6. Quantify Distribution Shift (Covariate & Label)
    print("\n[5/5] Computing distribution shift and error analysis...")
    shift_report = compute_distribution_shift(
        X_source_train,
        X_target_test,
        y_source_train,
        y_target_test,
        feature_names,
    )

    # Disagreement & Error Analysis on Target
    error_analysis = analyze_model_disagreements(
        y_target_aligned,
        aligned_tgt_rf,
        aligned_tgt_lstm,
        fusion_score=fusion_target_scores,
        threshold=0.5,
    )

    # Per-Family Breakdown on Target (if family provenance available)
    per_family_metrics: dict[str, Any] = {}
    if "label_family" in prov_target_test.columns:
        fams_aligned = prov_target_test["label_family"].iloc[target_aligned_idx].to_numpy()
        per_family_metrics = compute_per_family_metrics(
            y_target_aligned.to_numpy(),
            aligned_tgt_rf.to_numpy(),
            fams_aligned,
            threshold=0.5,
        )

    # Profiling
    profiler.__exit__(None, None, None)
    resource_info = profiler.to_dict()

    # 7. Write All Machine-Readable Artifacts
    print(f"\nWriting evaluation artifacts to {out_dir}...")
    (out_dir / "test_metrics.json").write_text(json.dumps(transfer_metrics, indent=2), encoding="utf-8")
    (out_dir / "transfer_comparison.json").write_text(json.dumps(degradation_table, indent=2), encoding="utf-8")
    (out_dir / "distribution_shift.json").write_text(json.dumps(shift_report, indent=2), encoding="utf-8")
    (out_dir / "error_analysis.json").write_text(json.dumps(error_analysis, indent=2), encoding="utf-8")
    (out_dir / "resource_profile.json").write_text(json.dumps(resource_info, indent=2), encoding="utf-8")

    if "summary_table" in per_family_metrics:
        pd.DataFrame(per_family_metrics["summary_table"]).to_csv(out_dir / "per_family_metrics.csv", index=False)

    # Build and write Experiment Record
    rf_tgt_metric = transfer_metrics["aligned"]["rf"]
    record = ExperimentRecord(
        experiment_id=exp_id,
        research_question="RQ5_CROSS_DATASET_TRANSFER",
        hypothesis=exp_cfg.get("hypothesis", "").strip(),
        dataset=target_key,
        dataset_sha256=target_pop.files[0].sha256 if target_pop.files else None,
        dataset_version=f"target_{target_key}",
        input_files=[f.filename for f in target_pop.files],
        rows_total=len(target_pop.features),
        rows_train=len(target_split.splits["train"]),
        rows_validation=len(target_split.splits["validation"]),
        rows_test=len(target_split.splits["test"]),
        feature_contract=contract_name,
        feature_list=feature_names,
        feature_schema_hash=feature_schema_hash(feature_names),
        preprocessing={
            "scaler": "StandardScaler",
            "fit_on": "source_train_only",
            "source_dataset": source_key,
            "target_dataset": target_key,
        },
        model={
            "name": "cross_dataset_transfer_suite",
            "source_models": {
                "majority": "MajorityClassDetector",
                "logistic_regression": "LogisticRegressionDetector",
                "decision_tree": "DecisionTreeDetector",
                "random_forest": "RandomForestDetector",
                "lstm": "LSTMDetector",
                "fusion": f"ScoreFusion(alpha={frozen_alpha:.2f})",
            },
        },
        hyperparameters={
            "source_dataset": source_key,
            "target_dataset": target_key,
            "contract": contract_name,
            "frozen_alpha": frozen_alpha,
            "threshold": 0.5,
        },
        random_seed=seed,
        threshold=0.5,
        threshold_decision_id="D-003",
        metrics={
            "aligned_population": len(target_aligned_idx),
            "rf": rf_tgt_metric,
            "lstm": transfer_metrics["aligned"]["lstm"],
            "fusion": transfer_metrics["aligned"]["fusion"],
        },
        confusion_matrix=rf_tgt_metric.get("confusion", {}),
        training_duration_s=resource_info.get("duration_s"),
        resource_profile=resource_info,
        status="EMPIRICALLY_OBSERVED",
        result_interpretation=(
            f"Under strict scientific isolation, detector trained on {source_key} achieves "
            f"{transfer_metrics['aligned']['fusion']['f1']:.4f} F1 on target {target_key} "
            f"under contract {contract_name} (degradation ΔF1 = {degradation_table[5]['delta_f1']:+.4f} vs source reference)."
        ),
        limitations=[
            "Zero target domain training or adaptation performed (pure out-of-domain transfer).",
            "Disparate background network topology and flow collection sensors introduce significant covariate shift.",
            "Decision D-003 (operational threshold) evaluated at neutral 0.5 baseline.",
        ],
        artifacts={
            "test_metrics": "test_metrics.json",
            "transfer_comparison": "transfer_comparison.json",
            "distribution_shift": "distribution_shift.json",
            "error_analysis": "error_analysis.json",
            "resource_profile": "resource_profile.json",
            "experiment_card": "experiment_card.md",
        },
        git_commit=git_commit() or "uncommitted",
        execution_commit=git_commit() or "uncommitted",
    )

    write_experiment_record(record, out_dir / "experiment_record.json")

    # Generate and write Experiment Card & Report
    card_md = generate_transfer_card(
        record,
        target_pop,
        source_dataset=source_key,
        target_dataset=target_key,
        contract_name=contract_name,
        feature_names=feature_names,
        source_reference=src_ref_aligned,
        transfer_metrics=transfer_metrics,
        degradation_table=degradation_table,
        shift_report=shift_report,
        error_analysis=error_analysis,
        per_family_metrics=per_family_metrics,
        resource_info=resource_info,
        frozen_alpha=frozen_alpha,
    )
    (out_dir / "experiment_card.md").write_text(card_md, encoding="utf-8")
    (out_dir / "experiment_report.md").write_text(card_md, encoding="utf-8")

    print(f"\n[DONE] Transfer experiment {exp_id} completed successfully in {time.time() - start_time:.2f}s!")
    print(f"Summary Table for {exp_id}:")
    print(f"{'Model':<20} | {'Source F1':<10} | {'Transfer F1':<12} | {'ΔF1':<10} | {'Source FPR':<10} | {'Transfer FPR':<12}")
    print("-" * 80)
    for row in degradation_table:
        print(f"{row['model_name']:<20} | {row['source_f1']:<10.4f} | {row['transfer_f1']:<12.4f} | {row['delta_f1']:<+10.4f} | {row['source_fpr']:<10.4f} | {row['transfer_fpr']:<12.4f}")

    return {
        "experiment_id": exp_id,
        "source": source_key,
        "target": target_key,
        "contract": contract_name,
        "degradation_table": degradation_table,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cross-dataset transfer experiments.")
    parser.add_argument(
        "--direction",
        choices=[
            "cic_to_cse_r10",
            "cse_to_cic_r10",
            "unsw_to_cic_r4",
            "unsw_to_cse_r4",
            "cic_to_unsw_r4",
            "cse_to_unsw_r4",
            "all",
        ],
        default="all",
        help="Transfer direction to execute (or 'all' for full 6-direction matrix)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    args = parser.parse_args()

    directions = {
        "cic_to_cse_r10": Path("configs/experiments/p1_transfer_cic_to_cse_r10.yaml"),
        "cse_to_cic_r10": Path("configs/experiments/p1_transfer_cse_to_cic_r10.yaml"),
        "unsw_to_cic_r4": Path("configs/experiments/p1_transfer_unsw_to_cic_r4.yaml"),
        "unsw_to_cse_r4": Path("configs/experiments/p1_transfer_unsw_to_cse_r4.yaml"),
        "cic_to_unsw_r4": Path("configs/experiments/p1_transfer_cic_to_unsw_r4.yaml"),
        "cse_to_unsw_r4": Path("configs/experiments/p1_transfer_cse_to_unsw_r4.yaml"),
    }

    selected = list(directions.keys()) if args.direction == "all" else [args.direction]
    results = []

    total_start = time.time()
    for d in selected:
        res = execute_transfer_direction(directions[d], seed=args.seed)
        results.append(res)

    print(f"\n{'='*80}")
    print(f"ALL SELECTED TRANSFER EXPERIMENTS COMPLETED IN {time.time() - total_start:.2f}s")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
