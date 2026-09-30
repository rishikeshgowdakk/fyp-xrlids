#!/usr/bin/env python
"""Phase 1 Unified Experiment Runner (build spec sections 28, 30, 31, 38).

Executes a complete, reproducible Phase-1 experiment from a declarative YAML config:
    python scripts/phase1/run_experiment.py --config configs/experiments/p1_cse_cic_ids2018_r10.yaml

Generates complete provenance:
    Config -> Dataset -> Clean -> Split -> Leakage Audit -> Preprocessor (train only)
           -> Random Forest -> Supervised LSTM -> Fusion (tuned on val)
           -> Calibration -> Thresholding (candidates) -> Error Analysis
           -> SHAP Attributions -> Experiment Record -> Markdown Report
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

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact  # noqa: E402
from xrlids.datasets.loading import dataset_availability, load_manifest  # noqa: E402
from xrlids.evaluation.calibration import PlattCalibrator, calibration_report  # noqa: E402
from xrlids.evaluation.error_analysis import (  # noqa: E402
    analyze_model_disagreements,
    compute_error_analysis,
)
from xrlids.evaluation.metrics import evaluate  # noqa: E402
from xrlids.evaluation.thresholding import (  # noqa: E402
    candidate_operating_points,
    threshold_sweep,
)
from xrlids.experiments.registry import (  # noqa: E402
    ExperimentRecord,
    load_yaml_config,
    make_experiment_id,
    write_experiment_record,
)
from xrlids.explainability.shap_analysis import compute_rf_shap_explanations  # noqa: E402
from xrlids.features.compute import compute_features, extract_semantics  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.models.fusion import align_scores, fuse_scores, tune_fusion_alpha  # noqa: E402
from xrlids.models.lstm import (  # noqa: E402
    LSTMDetector,
    assert_no_boundary_crossing,
    build_sequences,
)
from xrlids.models.random_forest import RandomForestDetector  # noqa: E402
from xrlids.preprocessing.cleaning import clean_dataset_frame  # noqa: E402
from xrlids.preprocessing.pipeline import Preprocessor  # noqa: E402
from xrlids.splitting.splitter import SplitConfig, build_splits  # noqa: E402
from xrlids.utils.env import environment_fingerprint, git_commit  # noqa: E402
from xrlids.utils.hashing import sha256_file  # noqa: E402
from xrlids.utils.logging_utils import get_logger  # noqa: E402
from xrlids.utils.seeding import set_global_seeds  # noqa: E402

logger = get_logger("run_experiment")


def generate_experiment_markdown_report(
    record: ExperimentRecord,
    metrics: dict[str, Any],
    error_analysis: dict[str, Any],
    shap_data: dict[str, Any] | None,
    transfer_data: dict[str, Any] | None,
) -> str:
    """Generate human-readable Markdown summary report from actual measured artifacts."""
    lines = [
        f"# Phase 1 Experiment Report: `{record.experiment_id}`",
        "",
        f"- **Status**: `{record.status}`",
        f"- **Dataset**: `{record.dataset}` (Version: `{record.dataset_version or 'N/A'}`)",
        f"- **SHA-256**: `{record.dataset_sha256 or 'N/A'}`",
        f"- **Feature Contract**: `{record.feature_contract}` ({len(record.feature_list)} features, Hash: `{record.feature_schema_hash}`)",
        f"- **Random Seed**: `{record.random_seed}`",
        f"- **Git Commit**: `{record.git_commit or 'uncommitted'}`",
        f"- **Execution Duration**: `{record.training_duration_s:.2f}s`" if record.training_duration_s else "- **Duration**: N/A",
        "",
        "---",
        "## 1. Population and Split Counts",
        "",
        f"- **Total Rows**: {record.rows_total:,}",
        f"- **Train Rows**: {record.rows_train:,}",
        f"- **Validation Rows**: {record.rows_validation:,}",
        f"- **Test Rows**: {record.rows_test:,}",
        "",
        "---",
        "## 2. Test Set Evaluation Metrics (Operating Point: 0.5)",
        "",
        "> [!NOTE]",
        "> Threshold 0.5 is a neutral reporting baseline. Decision **D-003** (threshold objective) remains OPEN.",
        "",
        "| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for model_name, m in metrics.items():
        if isinstance(m, dict) and "accuracy" in m:
            lines.append(
                f"| **{model_name.upper()}** | {m.get('population', 'N/A')} | "
                f"{m.get('accuracy', 0.0):.4f} | {m.get('precision', 0.0):.4f} | {m.get('recall', 0.0):.4f} | "
                f"{m.get('f1', 0.0):.4f} | {m.get('specificity', 0.0):.4f} | {m.get('fpr', 0.0):.4f} | "
                f"{m.get('roc_auc', 0.0):.4f} | {m.get('pr_auc', 0.0):.4f} |"
            )

    lines += [
        "",
        "---",
        "## 3. Model Disagreement and Fusion Analysis",
        "",
    ]
    dis = error_analysis.get("model_disagreements", {})
    if dis:
        lines += [
            f"- **Aligned Evaluation Population**: {dis.get('aligned_population_size', 0):,} rows",
            f"- **RF vs LSTM Disagreements**: {dis.get('disagreement_count', 0):,} ({dis.get('disagreement_fraction', 0.0) * 100:.2f}%)",
            f"- **RF Predicted Attack, LSTM Predicted Benign**: {dis.get('rf_pos_lstm_neg', {}).get('count', 0)} "
            f"(RF Correct: {dis.get('rf_pos_lstm_neg', {}).get('true_attacks_rf_right', 0)}, "
            f"RF False Alarm: {dis.get('rf_pos_lstm_neg', {}).get('true_benign_rf_false_alarm', 0)})",
            f"- **LSTM Predicted Attack, RF Predicted Benign**: {dis.get('rf_neg_lstm_pos', {}).get('count', 0)} "
            f"(LSTM Correct: {dis.get('rf_neg_lstm_pos', {}).get('true_attacks_lstm_right', 0)}, "
            f"LSTM False Alarm: {dis.get('rf_neg_lstm_pos', {}).get('true_benign_lstm_false_alarm', 0)})",
        ]
        fus = dis.get("fusion_analysis")
        if fus:
            lines += [
                f"- **Fusion Rescues When One Model Failed**: {fus.get('fusion_rescues_when_one_model_failed', 0)}",
                f"- **Fusion Rescues When Both Models Failed**: {fus.get('fusion_rescues_when_both_models_failed', 0)}",
                f"- **Fusion Degradations (Both Right, Fusion Wrong)**: {fus.get('fusion_degradations_when_both_were_right', 0)}",
            ]

    if shap_data and shap_data.get("global_importance"):
        lines += [
            "",
            "---",
            "## 4. SHAP Feature Attribution (Random Forest)",
            "",
            "> [!IMPORTANT]",
            "> SHAP quantifies additive associative contributions relative to the background expectation.",
            "> It does **NOT** prove causality in underlying network traffic.",
            "",
            "| Rank | Feature Name | Mean Absolute SHAP Value |",
            "| --- | --- | --- |",
        ]
        for item in shap_data["global_importance"][:10]:
            lines.append(f"| {item['rank']} | `{item['feature']}` | {item['mean_abs_shap']:.6f} |")

    if transfer_data:
        lines += [
            "",
            "---",
            "## 5. Cross-Dataset Transfer Analysis",
            "",
            f"- **Target Dataset**: `{transfer_data.get('target_dataset')}`",
            f"- **Common Transfer Features ({transfer_data.get('common_transfer_count')})**: `{', '.join(transfer_data.get('common_transfer_features', []))}`",
            f"- **Excluded Features Lacked by Target**: `{', '.join(transfer_data.get('source_only_supported', []))}`",
            f"- **Scientific Note**: {transfer_data.get('scientific_note')}",
            f"- **Target Availability**: `{transfer_data.get('target_availability', 'UNKNOWN')}`",
        ]
        if "transfer_metrics" in transfer_data:
            tm = transfer_data["transfer_metrics"]
            lines += [
                "",
                "### Transfer Evaluation Performance on Target Dataset",
                f"- **Accuracy**: {tm.get('accuracy', 0.0):.4f}",
                f"- **Precision**: {tm.get('precision', 0.0):.4f}",
                f"- **Recall**: {tm.get('recall', 0.0):.4f}",
                f"- **F1**: {tm.get('f1', 0.0):.4f}",
                f"- **ROC-AUC**: {tm.get('roc_auc', 0.0):.4f}",
            ]

    lines += [
        "",
        "---",
        "## 6. Open Decisions and Scientific Limitations",
        "",
        "- **Decision D-002 (Feature Contract)**: Features evaluated on R10/transfer contracts; formal freeze requires researcher confirmation.",
        "- **Decision D-003 (Threshold Objective)**: Evaluated at neutral 0.5 point; optimal threshold selection remains open.",
        "- **Duplicate Policy**: Duplicate feature vectors handled explicitly according to configuration.",
        "",
    ]

    return "\n".join(lines)


def run_experiment(
    config_path: str | Path,
    *,
    sample_limit: int | None = None,
    out_dir: str | Path | None = None,
    skip_shap: bool = False,
    skip_lstm: bool = False,
    transfer_target: str | None = None,
) -> int:
    config = load_yaml_config(config_path)
    exp_cfg = config.get("experiment", {})
    dataset_cfg = config.get("dataset", {})
    split_cfg = config.get("split", {})
    features_cfg = config.get("features", {})
    models_cfg = config.get("models", {})
    shap_cfg = config.get("explainability", {}).get("shap", {})

    seed = int(split_cfg.get("seed", 42))
    set_global_seeds(seed)
    started_time = time.time()

    dataset_key = dataset_cfg.get("key") or config.get("source_dataset", {}).get("key")
    if not dataset_key:
        print("ERROR: config missing dataset key", file=sys.stderr)
        return 1

    # Check manifest availability
    manifest = load_manifest()
    avail = dataset_availability(manifest, dataset_key)

    if avail["status"] != "available" and not avail.get("existing_files"):
        print(f"\n=======================================================", file=sys.stderr)
        print(f"DATA_NOT_AVAILABLE: Dataset '{dataset_key}' is not available on disk.", file=sys.stderr)
        print(f"Missing files for '{dataset_key}':", file=sys.stderr)
        for f in avail.get("missing_files", []):
            print(f"  - {f}", file=sys.stderr)
        print("\nAcquisition instructions:", file=sys.stderr)
        print(f"Place the raw CSV files into: data/raw/{dataset_key}/", file=sys.stderr)
        print(f"=======================================================\n", file=sys.stderr)
        return 2

    # Determine input file path
    file_name = dataset_cfg.get("file") or config.get("source_dataset", {}).get("file")
    if file_name:
        raw_file_path = Path("data/raw") / dataset_key / file_name
    else:
        existing = avail.get("existing_files", [])
        if existing:
            raw_file_path = Path("data/raw") / dataset_key / existing[0]
        else:
            print(f"ERROR: No files found for {dataset_key}", file=sys.stderr)
            return 2

    if not raw_file_path.is_file():
        print(f"DATA_NOT_AVAILABLE: {raw_file_path} not found on disk.", file=sys.stderr)
        return 2

    print(f"\n[1/10] Loading raw data: {raw_file_path} ...")
    raw_df = pd.read_csv(raw_file_path, low_memory=False)
    raw_sha256 = sha256_file(raw_file_path)
    total_raw_rows = len(raw_df)
    print(f"       Loaded {total_raw_rows:,} rows, 80 columns. SHA-256: {raw_sha256[:16]}...")

    is_subsample = False
    if sample_limit and sample_limit < total_raw_rows:
        print(f"       Applying development stratified sample limit: {sample_limit:,} rows (PRELIMINARY_SUBSAMPLE mode)")
        sample_indices: list[int] = []
        label_col = "Label" if "Label" in raw_df.columns else "label"
        frac = min(1.0, float(sample_limit / total_raw_rows))
        for _, group_df in raw_df.groupby(label_col):
            n_sample = max(1, int(round(len(group_df) * frac)))
            sampled = group_df.sample(n=min(len(group_df), n_sample), random_state=seed)
            sample_indices.extend(sampled.index)
        raw_df = raw_df.loc[sorted(sample_indices)].copy().reset_index(drop=True)
        is_subsample = True

    # Setup directories
    exp_id = exp_cfg.get("id", f"EXP-P1-{dataset_key.upper()}-{int(time.time())}")
    output_dir = Path(out_dir or config.get("outputs", {}).get("results_dir", f"results/experiments/{exp_id}"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Clean dataset and validate labels
    print("[2/10] Applying label contract and cleaning rules...")
    contract = load_label_contract()
    cleaned = clean_dataset_frame(raw_df, dataset_key, contract)
    labels = cleaned.labels.binary
    clean_df = cleaned.frame

    # 2. Features
    print("[3/10] Resolving feature contract...")
    registry = load_feature_registry()
    rung = features_cfg.get("rung", "R10")
    transfer_mode = features_cfg.get("mode") == "programmatic_common_transfer_contract"

    target_key = transfer_target or config.get("target_dataset", {}).get("key")
    transfer_audit = None

    if transfer_mode and target_key:
        feature_names = registry.common_transfer_contract(dataset_key, target_key, candidate_features=rung)
        transfer_audit = registry.transfer_compatibility_report(dataset_key, target_key, candidate_features=rung)
        print(f"       Transfer mode: programmatically selected {len(feature_names)} common features: {feature_names}")
    else:
        feature_names = registry.rung_features(rung)
        print(f"       In-domain mode: using {rung} contract ({len(feature_names)} features)")

    semantics, extraction_report = extract_semantics(clean_df, dataset_key, registry, strict=True)
    feature_matrix, available_feats, unavail_feats = compute_features(
        semantics, feature_names, dataset=dataset_key, strict=False
    )

    if unavail_feats:
        print(f"WARNING: Unavailable features for {dataset_key}: {unavail_feats}", file=sys.stderr)

    # Filter non-finite rows
    finite_mask = np.isfinite(feature_matrix[available_feats].to_numpy(dtype=float)).all(axis=1)
    feature_matrix = feature_matrix.loc[finite_mask].reset_index(drop=True)
    labels = labels.loc[finite_mask].reset_index(drop=True)
    clean_df = clean_df.loc[finite_mask].reset_index(drop=True)

    # 3. Splits with duplicate policy
    dup_policy = split_cfg.get("duplicate_policy", "deduplicate_features")
    print(f"[4/10] Generating splits with duplicate policy: '{dup_policy}'...")
    split_configuration = SplitConfig(
        train=float(split_cfg.get("train", 0.6)),
        validation=float(split_cfg.get("validation", 0.2)),
        test=float(split_cfg.get("test", 0.2)),
        seed=seed,
        methodology=split_cfg.get("methodology", "stratified_random"),
        rationale=f"Split with duplicate_policy={dup_policy}",
        duplicate_policy=dup_policy,
    )
    split_result = build_splits(
        feature_matrix,
        labels,
        available_feats,
        split_configuration,
        dataset=dataset_key,
        run_leakage_audit=split_cfg.get("leakage_audit_required", True),
    )

    train_df = split_result.splits["train"]
    val_df = split_result.splits["validation"]
    test_df = split_result.splits["test"]

    y_train = split_result.label_splits["train"]
    y_val = split_result.label_splits["validation"]
    y_test = split_result.label_splits["test"]

    print(f"       Split counts -> Train: {len(train_df):,}, Val: {len(val_df):,}, Test: {len(test_df):,}")
    leakage_status = split_result.leakage.get("status", "unknown")
    print(f"       Leakage audit status: {leakage_status}")
    if leakage_status == "fail" and dup_policy != "retain_with_subset_evaluation":
        print(f"ERROR: Leakage audit failed: {split_result.leakage.get('failed_checks')}", file=sys.stderr)
        if split_cfg.get("fail_on_leakage", True):
            print("Aborting experiment due to split leakage.", file=sys.stderr)
            return 1

    # 4. Preprocessing: Fit on TRAIN ONLY
    print("[5/10] Fitting preprocessing on TRAIN ONLY...")
    preprocessor = Preprocessor(features=available_feats, dataset=dataset_key).fit(train_df)
    X_train = preprocessor.transform(train_df)
    X_val = preprocessor.transform(val_df)
    X_test = preprocessor.transform(test_df)

    # 5. Random Forest Baseline
    print("[6/10] Training Random Forest baseline...")
    rf_params = dict(models_cfg.get("random_forest", {}))
    rf = RandomForestDetector(params=rf_params, feature_names=available_feats).fit(X_train, y_train)
    rf_val = pd.Series(rf.predict_proba(X_val), index=X_val.index, name="rf_score")
    rf_test = pd.Series(rf.predict_proba(X_test), index=X_test.index, name="rf_score")

    # 6. Supervised LSTM
    lstm = None
    lstm_val = pd.Series([], dtype=float)
    lstm_test = pd.Series([], dtype=float)
    y_val_seq = pd.Series([], dtype=int)
    y_test_seq = pd.Series([], dtype=int)

    if not skip_lstm:
        print("[7/10] Training Supervised LSTM (boundary-safe sequence construction)...")
        lstm_params = dict(models_cfg.get("lstm", {}))
        seq_len = int(lstm_params.pop("seq_len", 5))
        stride = int(lstm_params.pop("stride", 1))
        label_rule = lstm_params.pop("label_rule", "last")

        train_seqs = build_sequences(X_train, y_train, split="train", seq_len=seq_len, stride=stride, label_rule=label_rule)
        val_seqs = build_sequences(X_val, y_val, split="validation", seq_len=seq_len, stride=stride, label_rule=label_rule)
        test_seqs = build_sequences(X_test, y_test, split="test", seq_len=seq_len, stride=stride, label_rule=label_rule)

        assert_no_boundary_crossing(
            [train_seqs, val_seqs, test_seqs],
            {"train": len(X_train), "validation": len(X_val), "test": len(X_test)},
        )

        lstm = LSTMDetector(params=lstm_params, feature_names=available_feats, seq_len=seq_len, seed=seed)
        lstm.fit(train_seqs, val_seqs)

        lstm_val_scores = lstm.predict_proba(val_seqs)
        lstm_test_scores = lstm.predict_proba(test_seqs)

        lstm_val = pd.Series(lstm_val_scores, index=val_seqs.origins + seq_len - 1, name="lstm_score")
        lstm_test = pd.Series(lstm_test_scores, index=test_seqs.origins + seq_len - 1, name="lstm_score")
        y_val_seq = pd.Series(y_val.to_numpy()[lstm_val.index], index=lstm_val.index)
        y_test_seq = pd.Series(y_test.to_numpy()[lstm_test.index], index=lstm_test.index)
    else:
        print("[7/10] Skipping LSTM as requested.")

    # 7. Fusion
    print("[8/10] Evaluating aligned models and score fusion...")
    test_metrics: dict[str, Any] = {
        "rf": evaluate(y_test, rf_test, threshold=0.5),
    }

    fusion_tuning = None
    fusion_test_series = None
    aligned_test_rf = rf_test
    aligned_test_lstm = lstm_test
    y_test_aligned = y_test

    if len(lstm_test) > 0:
        test_metrics["lstm"] = evaluate(y_test_seq, lstm_test, threshold=0.5)

        # Align on validation
        aligned_val_rf, aligned_val_lstm, _ = align_scores(rf_val, lstm_val, how="inner")
        y_val_aligned = pd.Series(y_val.to_numpy()[aligned_val_rf.index], index=aligned_val_rf.index)

        # Tune alpha on validation
        fusion_tuning = tune_fusion_alpha(aligned_val_rf, aligned_val_lstm, y_val_aligned, metric="roc_auc")
        alpha = fusion_tuning["best_alpha"]
        print(f"       Validation tuned fusion weight alpha: {alpha:.2f} (metric={fusion_tuning['target_metric']} val={fusion_tuning['best_metric_value']:.4f})")

        # Evaluate fusion on test
        aligned_test_rf, aligned_test_lstm, align_test_report = align_scores(rf_test, lstm_test, how="inner")
        y_test_aligned = pd.Series(y_test.to_numpy()[aligned_test_rf.index], index=aligned_test_rf.index)

        fusion_res = fuse_scores(aligned_test_rf, aligned_test_lstm, alpha=alpha, how="strict")
        fusion_test_series = pd.Series(fusion_res.scores, index=aligned_test_rf.index, name="fusion_score")
        test_metrics["fusion"] = evaluate(y_test_aligned, fusion_res.scores, threshold=0.5)

    # 8. Calibration & Thresholding
    print("[9/10] Calibration and threshold analysis...")
    cal_rf = calibration_report(y_val, rf_val).to_dict()
    cal_lstm = calibration_report(y_val_seq, lstm_val).to_dict() if len(lstm_val) else None
    cal_fusion = None

    test_calibration: dict[str, Any] = {}
    try:
        platt_rf = PlattCalibrator().fit(y_val, rf_val)
        calibrated_test_rf = platt_rf.transform(rf_test)
        test_calibration["rf"] = calibration_report(y_test, calibrated_test_rf).to_dict()

        if fusion_test_series is not None:
            aligned_val_rf, aligned_val_lstm, _ = align_scores(rf_val, lstm_val, how="inner")
            y_val_aligned = pd.Series(y_val.to_numpy()[aligned_val_rf.index], index=aligned_val_rf.index)
            fus_val_scores = alpha * aligned_val_rf.to_numpy(dtype=float) + (1.0 - alpha) * aligned_val_lstm.to_numpy(dtype=float)
            cal_fusion = calibration_report(y_val_aligned, fus_val_scores).to_dict()

            platt_fus = PlattCalibrator().fit(y_val_aligned, fus_val_scores)
            calibrated_test_fus = platt_fus.transform(fusion_test_series.to_numpy(dtype=float))
            test_calibration["fusion"] = calibration_report(y_test_aligned, calibrated_test_fus).to_dict()
    except Exception as exc:
        test_calibration["note"] = f"Calibration notice: {exc}"

    # Validation threshold sweep for D-003
    eval_val_scores = rf_val if fusion_test_series is None else pd.Series(fus_val_scores, index=y_val_aligned.index)
    eval_val_y = y_val if fusion_test_series is None else y_val_aligned
    val_sweep = threshold_sweep(eval_val_y, eval_val_scores)
    threshold_candidates = candidate_operating_points(val_sweep)

    # Error analysis
    error_analysis = {
        "rf": compute_error_analysis(y_test, rf_test, threshold=0.5, features_df=test_df, duplicate_mask=split_result.test_duplicate_mask),
    }
    if len(lstm_test) > 0 and fusion_test_series is not None:
        error_analysis["lstm"] = compute_error_analysis(y_test_seq, lstm_test, threshold=0.5)
        error_analysis["fusion"] = compute_error_analysis(
            y_test_aligned, fusion_test_series, threshold=0.5,
            duplicate_mask=split_result.test_duplicate_mask.iloc[aligned_test_rf.index].reset_index(drop=True) if split_result.test_duplicate_mask is not None else None
        )
        error_analysis["model_disagreements"] = analyze_model_disagreements(
            y_test_aligned, aligned_test_rf, aligned_test_lstm, fusion_score=fusion_test_series, threshold=0.5
        )

    # 9. SHAP Explainability
    shap_summary = None
    if not skip_shap and shap_cfg.get("enabled", True):
        print("[10/10] Computing TreeSHAP explainability...")
        try:
            shap_summary = compute_rf_shap_explanations(
                rf,
                X_background=X_train,
                X_explain=X_test,
                y_explain=y_test,
                feature_names=available_feats,
                max_background=int(shap_cfg.get("max_background", 100)),
                max_explain=int(shap_cfg.get("max_explain", 200)),
                seed=seed,
            )
            print(f"        SHAP top feature: {shap_summary['global_importance'][0]['feature']} (mean |SHAP|={shap_summary['global_importance'][0]['mean_abs_shap']:.4f})")
        except Exception as exc:
            print(f"WARNING: SHAP computation failed: {exc}", file=sys.stderr)
    else:
        print("[10/10] Skipping SHAP computation.")

    # Cross-dataset transfer evaluation
    transfer_results = None
    if target_key:
        target_avail = dataset_availability(manifest, target_key)
        transfer_results = transfer_audit or registry.transfer_compatibility_report(dataset_key, target_key, candidate_features=available_feats)
        transfer_results["target_availability"] = target_avail["status"]

        if target_avail["status"] == "available" and target_avail.get("existing_files"):
            # Target dataset is physically present! Evaluate transfer performance
            try:
                target_file_path = Path("data/raw") / target_key / target_avail["existing_files"][0]
                target_raw = pd.read_csv(target_file_path, low_memory=False)
                target_cleaned = clean_dataset_frame(target_raw, target_key, contract)
                target_semantics, _ = extract_semantics(target_cleaned.frame, target_key, registry, strict=True)
                target_fm, _, _ = compute_features(target_semantics, transfer_results["common_transfer_features"], dataset=target_key, strict=False)
                target_finite = np.isfinite(target_fm.to_numpy(dtype=float)).all(axis=1)
                target_fm = target_fm.loc[target_finite].reset_index(drop=True)
                target_y = target_cleaned.labels.binary.loc[target_finite].reset_index(drop=True)

                # Preprocessor transform ONLY (never fit on target!)
                target_X = preprocessor.transform(target_fm)
                target_preds = rf.predict_proba(target_X)
                transfer_results["transfer_metrics"] = evaluate(target_y, target_preds, threshold=0.5)
                print(f"        Target dataset '{target_key}' transfer evaluation complete: F1={transfer_results['transfer_metrics'].get('f1'):.4f}")
            except Exception as exc:
                transfer_results["transfer_error"] = str(exc)
        else:
            print(f"        Target dataset '{target_key}' is DATA_NOT_AVAILABLE. Recorded contract without fabricating results.")

    duration_s = time.time() - started_time

    # 10. Save Artifacts
    print(f"\nWriting experiment artifacts to: {output_dir}/")
    rf.save(output_dir)
    if lstm is not None:
        lstm.save(output_dir)
    preprocessor.save(output_dir)

    # Save predictions
    preds_dict = {
        "true_label": y_test_aligned.to_numpy(),
        "rf_score": aligned_test_rf.to_numpy(),
    }
    if len(lstm_test) > 0 and fusion_test_series is not None:
        preds_dict["lstm_score"] = aligned_test_lstm.to_numpy()
        preds_dict["fusion_score"] = fusion_test_series.to_numpy()
    preds_df = pd.DataFrame(preds_dict, index=y_test_aligned.index)
    preds_csv = output_dir / "predictions_test.csv"
    preds_df.to_csv(preds_csv, index=True)

    # Write manifests and JSON artifacts
    (output_dir / "split_manifest.json").write_text(json.dumps(split_result.manifest, indent=2, default=str), encoding="utf-8")
    (output_dir / "leakage_report.json").write_text(json.dumps(split_result.leakage, indent=2, default=str), encoding="utf-8")
    (output_dir / "preprocessor_metadata.json").write_text(json.dumps(preprocessor.metadata(), indent=2, default=str), encoding="utf-8")
    (output_dir / "test_metrics.json").write_text(json.dumps(test_metrics, indent=2, default=str), encoding="utf-8")
    (output_dir / "error_analysis.json").write_text(json.dumps(error_analysis, indent=2, default=str), encoding="utf-8")
    (output_dir / "calibration_report.json").write_text(json.dumps({
        "validation_calibration": {"rf": cal_rf, "lstm": cal_lstm, "fusion": cal_fusion},
        "test_calibration": test_calibration,
    }, indent=2, default=str), encoding="utf-8")
    (output_dir / "threshold_candidates.json").write_text(json.dumps(threshold_candidates, indent=2, default=str), encoding="utf-8")

    if shap_summary is not None:
        (output_dir / "shap_summary.json").write_text(json.dumps(shap_summary, indent=2, default=str), encoding="utf-8")
    if transfer_results is not None:
        (output_dir / "transfer_report.json").write_text(json.dumps(transfer_results, indent=2, default=str), encoding="utf-8")

    # Experiment Record
    dataset_entry = next((d for d in manifest.get("datasets", []) if d.get("key") == dataset_key), {})
    dataset_ver = dataset_entry.get("version", "1.0.0")
    record = ExperimentRecord(
        experiment_id=exp_id,
        research_question=exp_cfg.get("research_question", "RQ1"),
        hypothesis=exp_cfg.get("hypothesis", ""),
        dataset=dataset_key,
        dataset_sha256=raw_sha256,
        dataset_version=dataset_ver,
        input_files=[str(raw_file_path)],
        rows_total=int(len(clean_df)),
        rows_train=int(len(train_df)),
        rows_validation=int(len(val_df)),
        rows_test=int(len(test_df)),
        feature_contract=rung if not transfer_mode else f"transfer_common_{len(available_feats)}",
        feature_list=available_feats,
        feature_schema_hash=registry.schema_hash(rung) if not transfer_mode else transfer_results.get("schema_hash"),
        preprocessing=preprocessor.metadata(),
        split_id=split_result.manifest.get("split_config_hash"),
        model=rf.config(),
        hyperparameters={"rf": rf_params, "split": split_cfg, "duplicate_policy": dup_policy},
        random_seed=seed,
        threshold=0.5,
        threshold_decision_id="D-003",
        metrics=test_metrics,
        confusion_matrix=test_metrics["rf"]["confusion"],
        training_duration_s=duration_s,
        hardware="CPU (linux)",
        status=exp_status,
        result_interpretation=(
            "Preliminary validation run on subsampled data." if is_subsample
            else "Real-data empirical evaluation; test set evaluated post-hoc without model tuning."
        ),
        limitations=[
            "Threshold objective D-003 remains open; reporting uses neutral threshold 0.5.",
            "Feature contract D-002 candidate evaluation.",
            f"Duplicate policy applied: {dup_policy}.",
        ],
        artifacts={
            "predictions": str(preds_csv),
            "rf_model": str(output_dir / "random_forest.joblib"),
            "report": str(output_dir / "experiment_report.md"),
        },
        git_commit=git_commit(),
        software_environment=environment_fingerprint(),
    )
    write_experiment_record(record, output_dir / "experiment_record.json")

    # Generate Markdown report
    md_report = generate_experiment_markdown_report(
        record, test_metrics, error_analysis, shap_summary, transfer_results
    )
    (output_dir / "experiment_report.md").write_text(md_report, encoding="utf-8")

    print(f"\nExperiment execution complete in {duration_s:.2f}s!")
    print(f"Record: {output_dir / 'experiment_record.json'}")
    print(f"Report: {output_dir / 'experiment_report.md'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 1 Unified Experiment Runner")
    parser.add_argument("--config", required=True, help="Path to YAML experiment configuration")
    parser.add_argument("--sample-limit", type=int, default=None, help="Optional row subsample limit for development/debugging")
    parser.add_argument("--out-dir", default=None, help="Optional custom output directory")
    parser.add_argument("--skip-shap", action="store_true", help="Skip SHAP computation")
    parser.add_argument("--skip-lstm", action="store_true", help="Skip Supervised LSTM training")
    parser.add_argument("--transfer-target", default=None, help="Target dataset for cross-dataset transfer evaluation")
    args = parser.parse_args()

    return run_experiment(
        args.config,
        sample_limit=args.sample_limit,
        out_dir=args.out_dir,
        skip_shap=args.skip_shap,
        skip_lstm=args.skip_lstm,
        transfer_target=args.transfer_target,
    )


if __name__ == "__main__":
    raise SystemExit(main())
