#!/usr/bin/env python
"""Phase 1 Unified Multi-File Experiment Runner (Build Spec Sections 28, 30, 31, 38).

Executes a complete, reproducible Phase-1 research experiment from a declarative YAML config:
    python scripts/phase1/run_experiment.py --config configs/experiments/p1_cicids2017_r10.yaml

Generates complete, auditable research evidence:
    Multi-File Population -> Verify Integrity (SHA-256) -> Clean & Validate
                          -> Duplicate Conflict Analysis -> Complete Reconciled Accounting
                          -> Leakage-Safe Splits -> Preprocessor (Train Only)
                          -> Baseline Ladder: Majority, Logistic Regression, Decision Tree,
                             Random Forest, Supervised LSTM, RF+LSTM Fusion
                          -> Fair Aligned Population Evaluation & Statistical Comparisons
                          -> Per-Attack-Family Evaluation -> Calibration & Threshold Sweeps
                          -> TreeSHAP Attributions -> Failure Error Analysis
                          -> Machine-Readable Manifests & Comprehensive Experiment Card
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
from xrlids.datasets.population import (  # noqa: E402
    DatasetPopulation,
    PopulationConfig,
    load_dataset_population,
)
from xrlids.evaluation.calibration import PlattCalibrator, calibration_report  # noqa: E402
from xrlids.evaluation.error_analysis import (  # noqa: E402
    analyze_model_disagreements,
    compute_error_analysis,
    compute_per_family_metrics,
    compute_stratified_dataset_summary,
)
from xrlids.evaluation.metrics import evaluate  # noqa: E402
from xrlids.evaluation.statistics import (  # noqa: E402
    bootstrap_metric_ci,
    multi_seed_summary,
    paired_model_comparison,
)
from xrlids.evaluation.thresholding import (  # noqa: E402
    candidate_operating_points,
    threshold_sweep,
)
from xrlids.experiments.card import generate_experiment_card  # noqa: E402
from xrlids.experiments.preflight import (  # noqa: E402
    PreflightValidationError,
    validate_experiment_preflight,
)
from xrlids.experiments.registry import (  # noqa: E402
    ExperimentRecord,
    load_yaml_config,
    write_experiment_record,
)
from xrlids.explainability.shap_analysis import compute_rf_shap_explanations  # noqa: E402
from xrlids.features.compute import compute_features, extract_semantics  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.models.baselines import (  # noqa: E402
    DecisionTreeDetector,
    LogisticRegressionDetector,
    MajorityClassDetector,
)
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
from xrlids.utils.logging_utils import get_logger  # noqa: E402
from xrlids.utils.profiler import ResourceProfiler  # noqa: E402
from xrlids.utils.seeding import set_global_seeds  # noqa: E402

logger = get_logger("run_experiment")


def run_experiment_pipeline(
    config: dict[str, Any],
    seed: int,
    *,
    sample_limit: int | None = None,
    out_dir: Path,
    skip_shap: bool = False,
    skip_lstm: bool = False,
    transfer_target: str | None = None,
    max_memory_gb: float = 10.0,
) -> dict[str, Any]:
    """Execute a single deterministic experiment pass."""
    set_global_seeds(seed)
    started_time = time.time()

    dataset_cfg = config.get("dataset", {})
    split_cfg = config.get("split", {})
    features_cfg = config.get("features", {})
    models_cfg = config.get("models", {})
    shap_cfg = config.get("explainability", {}).get("shap", {})
    exp_cfg = config.get("experiment", {})

    dataset_key = dataset_cfg.get("key") or config.get("source_dataset", {}).get("key")
    if not dataset_key:
        raise ValueError("Configuration missing dataset key")

    # 1. Feature contract resolution
    registry = load_feature_registry()
    contract = load_label_contract()
    rung = features_cfg.get("rung", "R10")
    transfer_mode = features_cfg.get("mode") == "programmatic_common_transfer_contract"
    target_key = transfer_target or config.get("target_dataset", {}).get("key")

    if transfer_mode and target_key:
        feature_names = registry.common_transfer_contract(dataset_key, target_key, candidate_features=rung)
        print(f"       Transfer mode: programmatically selected {len(feature_names)} common features: {feature_names}")
    else:
        feature_names = registry.rung_features(rung)
        print(f"       In-domain mode: using {rung} contract ({len(feature_names)} features)")

    # 2. Multi-File Population Loading & Pre-flight
    files_spec = dataset_cfg.get("files") or dataset_cfg.get("file") or "all"
    pop_config = PopulationConfig(
        dataset=dataset_key,
        files=files_spec,
        exclude_files=dataset_cfg.get("exclude_files", []),
        file_order=dataset_cfg.get("file_order", "manifest"),
        require_verified_checksums=bool(dataset_cfg.get("require_verified_checksums", True)),
        require_schema_validated=bool(dataset_cfg.get("require_schema_validated", True)),
        duplicate_policy=split_cfg.get("duplicate_policy", "deduplicate_features"),
        duplicate_conflict_policy=split_cfg.get("duplicate_conflict_policy", "reject_conflicts"),
        sample_limit=sample_limit or dataset_cfg.get("sample_limit"),
        seed=seed,
    )

    manifest = load_manifest()
    avail = dataset_availability(manifest, dataset_key)
    if avail["status"] != "available" and not avail.get("existing_files"):
        raise RuntimeError(f"DATA_NOT_AVAILABLE: Dataset '{dataset_key}' is missing physical files.")

    # Determine files to validate pre-flight
    raw_files_to_validate = [
        Path(f["path"]) for f in manifest["datasets"][next(i for i, d in enumerate(manifest["datasets"]) if d["key"] == dataset_key)]["files"]
        if Path(f["path"]).is_file()
    ]
    if not raw_files_to_validate:
        raw_files_to_validate = sorted((Path("data/raw") / dataset_key).glob("*.csv"))

    print("\n[1/10] Pre-flight validation gate across dataset files...")
    preflight_res = validate_experiment_preflight(
        config,
        raw_files_to_validate,
        manifest=manifest,
        sample_limit=sample_limit,
    )
    print(f"       Pre-flight validation PASSED: {preflight_res['total_files']} files verified against SHA-256 and canonical schema.")

    # Start resource profiler
    profiler = ResourceProfiler(target_dir=out_dir)
    profiler.__enter__()

    # 3. Load full population with mathematical accounting and conflict analysis
    print(f"\n[2/10] Loading multi-file dataset population for '{dataset_key}'...")
    population = load_dataset_population(
        pop_config,
        feature_names,
        contract=contract,
        registry=registry,
    )
    feature_names = list(population.features.columns)
    print(
        f"       Population loaded: {population.accounting.aggregate['raw_rows']:,} raw rows "
        f"-> {len(population.features):,} final modeling rows across {len(population.files)} files."
    )
    print(
        f"       Active features ({len(feature_names)}): {feature_names}"
    )
    print(
        f"       Accounting reconciliation: {'RECONCILED' if population.accounting.reconciled else 'DEVELOPMENT_SUBSAMPLE'}"
    )
    if population.conflict_report.total_conflicting_vectors > 0:
        print(
            f"       Duplicate-label conflicts: {population.conflict_report.total_conflicting_vectors:,} vectors "
            f"({population.conflict_report.rows_dropped:,} rows dropped under policy '{pop_config.duplicate_conflict_policy}')."
        )

    # 4. Generate leakage-safe splits
    dup_policy = split_cfg.get("duplicate_policy", "deduplicate_features")
    print(f"\n[3/10] Generating splits with duplicate policy: '{dup_policy}'...")
    split_configuration = SplitConfig(
        train=float(split_cfg.get("train", 0.6)),
        validation=float(split_cfg.get("validation", 0.2)),
        test=float(split_cfg.get("test", 0.2)),
        seed=seed,
        methodology=split_cfg.get("methodology", "stratified_random"),
        rationale=f"Multi-file split with duplicate_policy={dup_policy}",
        duplicate_policy=dup_policy,
    )
    split_result = build_splits(
        population.features,
        population.labels,
        feature_names,
        split_configuration,
        dataset=dataset_key,
        provenance=population.provenance,
        run_leakage_audit=split_cfg.get("leakage_audit_required", True),
    )

    train_df = split_result.splits["train"]
    val_df = split_result.splits["validation"]
    test_df = split_result.splits["test"]

    y_train = split_result.label_splits["train"]
    y_val = split_result.label_splits["validation"]
    y_test = split_result.label_splits["test"]

    prov_train = split_result.provenance_splits.get("train", pd.DataFrame())
    prov_val = split_result.provenance_splits.get("validation", pd.DataFrame())
    prov_test = split_result.provenance_splits.get("test", pd.DataFrame())

    print(f"       Split counts -> Train: {len(train_df):,}, Val: {len(val_df):,}, Test: {len(test_df):,}")
    print(f"       Leakage audit: {split_result.leakage.get('status', 'unknown')}")

    # 5. Preprocessing (Fitted on TRAIN ONLY)
    print("\n[4/10] Fitting preprocessing on TRAIN ONLY (scientific isolation)...")
    preprocessor = Preprocessor(features=feature_names, dataset=dataset_key).fit(train_df)
    X_train = preprocessor.transform(train_df)
    X_val = preprocessor.transform(val_df)
    X_test = preprocessor.transform(test_df)

    # 6. Baseline Ladder Execution
    print("\n[5/10] Training Baseline Ladder (Majority Class, Logistic Regression, Decision Tree)...")
    maj = MajorityClassDetector().fit(X_train, y_train)
    maj_test = maj.predict_proba(X_test)

    lr = LogisticRegressionDetector(seed=seed).fit(X_train, y_train)
    lr_val = lr.predict_proba(X_val)
    lr_test = lr.predict_proba(X_test)

    dt = DecisionTreeDetector(seed=seed).fit(X_train, y_train)
    dt_val = dt.predict_proba(X_val)
    dt_test = dt.predict_proba(X_test)

    print("\n[6/10] Training Random Forest detector...")
    rf_params = dict(models_cfg.get("random_forest", {}))
    rf = RandomForestDetector(params=rf_params, feature_names=feature_names).fit(X_train, y_train)
    rf_val = pd.Series(rf.predict_proba(X_val), index=X_val.index, name="rf_score")
    rf_test = pd.Series(rf.predict_proba(X_test), index=X_test.index, name="rf_score")

    # 7. Supervised LSTM with Sequence Safety
    lstm = None
    lstm_val = pd.Series([], dtype=float)
    lstm_test = pd.Series([], dtype=float)
    y_val_seq = pd.Series([], dtype=int)
    y_test_seq = pd.Series([], dtype=int)

    if not skip_lstm:
        print("\n[7/10] Training Supervised LSTM (sequence boundary protected)...")
        lstm_params = dict(models_cfg.get("lstm", {}))
        seq_len = int(lstm_params.pop("seq_len", 5))
        stride = int(lstm_params.pop("stride", 1))
        label_rule = lstm_params.pop("label_rule", "last")

        train_session = prov_train["source_file"] if "source_file" in prov_train.columns else None
        val_session = prov_val["source_file"] if "source_file" in prov_val.columns else None
        test_session = prov_test["source_file"] if "source_file" in prov_test.columns else None

        train_seqs = build_sequences(X_train, y_train, split="train", seq_len=seq_len, stride=stride, label_rule=label_rule, session_column=train_session)
        val_seqs = build_sequences(X_val, y_val, split="validation", seq_len=seq_len, stride=stride, label_rule=label_rule, session_column=val_session)
        test_seqs = build_sequences(X_test, y_test, split="test", seq_len=seq_len, stride=stride, label_rule=label_rule, session_column=test_session)

        lstm = LSTMDetector(params=lstm_params, feature_names=feature_names, seq_len=seq_len, seed=seed)
        lstm.fit(train_seqs, val_seqs)

        lstm_val_scores = lstm.predict_proba(val_seqs)
        lstm_test_scores = lstm.predict_proba(test_seqs)

        lstm_val = pd.Series(lstm_val_scores, index=val_seqs.origins + seq_len - 1, name="lstm_score")
        lstm_test = pd.Series(lstm_test_scores, index=test_seqs.origins + seq_len - 1, name="lstm_score")
        y_val_seq = pd.Series(y_val.to_numpy()[lstm_val.index], index=lstm_val.index)
        y_test_seq = pd.Series(y_test.to_numpy()[lstm_test.index], index=lstm_test.index)
    else:
        print("\n[7/10] Skipping LSTM as requested.")

    # 8. Score Fusion & Standardized Populations
    print("\n[8/10] Standardizing populations and evaluating Fusion...")
    native_metrics: dict[str, Any] = {
        "majority": evaluate(y_test, maj_test, threshold=0.5),
        "logistic_regression": evaluate(y_test, lr_test, threshold=0.5),
        "decision_tree": evaluate(y_test, dt_test, threshold=0.5),
        "random_forest": evaluate(y_test, rf_test, threshold=0.5),
    }
    native_metrics["majority"]["family"] = "prior_baseline"
    native_metrics["logistic_regression"]["family"] = "linear_baseline"
    native_metrics["decision_tree"]["family"] = "tree_baseline"
    native_metrics["random_forest"]["family"] = "ensemble"

    # Aligned population (where both RF and LSTM have valid predictions)
    aligned_test_rf = rf_test
    aligned_test_lstm = lstm_test
    y_test_aligned = y_test
    fusion_tuning = None
    fusion_test_series = None
    alpha = 0.5

    if len(lstm_test) > 0:
        native_metrics["lstm"] = evaluate(y_test_seq, lstm_test, threshold=0.5)
        native_metrics["lstm"]["family"] = "temporal_recurrent"

        aligned_val_rf, aligned_val_lstm, _ = align_scores(rf_val, lstm_val, how="inner")
        y_val_aligned = pd.Series(y_val.to_numpy()[aligned_val_rf.index], index=aligned_val_rf.index)

        fusion_tuning = tune_fusion_alpha(aligned_val_rf, aligned_val_lstm, y_val_aligned, metric="roc_auc")
        alpha = fusion_tuning["best_alpha"]
        print(f"       Tuned validation fusion alpha: {alpha:.2f} (validation ROC-AUC: {fusion_tuning['best_metric_value']:.4f})")

        aligned_test_rf, aligned_test_lstm, _ = align_scores(rf_test, lstm_test, how="inner")
        y_test_aligned = pd.Series(y_test.to_numpy()[aligned_test_rf.index], index=aligned_test_rf.index)

        fusion_res = fuse_scores(aligned_test_rf, aligned_test_lstm, alpha=alpha, how="strict")
        fusion_test_series = pd.Series(fusion_res.scores, index=aligned_test_rf.index, name="fusion_score")

    # Evaluate all models on fair aligned population
    aligned_idx = aligned_test_rf.index
    aligned_metrics: dict[str, Any] = {
        "population_size": len(aligned_idx),
        "models": {
            "majority": evaluate(y_test.loc[aligned_idx], maj_test[aligned_idx], threshold=0.5),
            "logistic_regression": evaluate(y_test.loc[aligned_idx], lr_test[aligned_idx], threshold=0.5),
            "decision_tree": evaluate(y_test.loc[aligned_idx], dt_test[aligned_idx], threshold=0.5),
            "random_forest": evaluate(y_test_aligned, aligned_test_rf, threshold=0.5),
        },
    }
    aligned_metrics["models"]["majority"]["family"] = "prior_baseline"
    aligned_metrics["models"]["logistic_regression"]["family"] = "linear_baseline"
    aligned_metrics["models"]["decision_tree"]["family"] = "tree_baseline"
    aligned_metrics["models"]["random_forest"]["family"] = "ensemble"

    if fusion_test_series is not None:
        aligned_metrics["models"]["lstm"] = evaluate(y_test_aligned, aligned_test_lstm, threshold=0.5)
        aligned_metrics["models"]["lstm"]["family"] = "temporal_recurrent"
        aligned_metrics["models"]["fusion"] = evaluate(y_test_aligned, fusion_test_series, threshold=0.5)
        aligned_metrics["models"]["fusion"]["family"] = "ensemble_fusion"

    # Paired statistical comparisons (Task 19)
    statistical_comparisons: list[dict[str, Any]] = []
    yt_alg = y_test_aligned.to_numpy()
    statistical_comparisons.append(
        paired_model_comparison(yt_alg, lr_test[aligned_idx], dt_test[aligned_idx], model_a_name="LR", model_b_name="DT", seed=seed)
    )
    statistical_comparisons.append(
        paired_model_comparison(yt_alg, dt_test[aligned_idx], aligned_test_rf.to_numpy(), model_a_name="DT", model_b_name="RF", seed=seed)
    )
    if fusion_test_series is not None:
        statistical_comparisons.append(
            paired_model_comparison(yt_alg, aligned_test_rf.to_numpy(), aligned_test_lstm.to_numpy(), model_a_name="RF", model_b_name="LSTM", seed=seed)
        )
        statistical_comparisons.append(
            paired_model_comparison(yt_alg, fusion_test_series.to_numpy(), aligned_test_rf.to_numpy(), model_a_name="Fusion", model_b_name="RF", seed=seed)
        )

    # 9. Per-Attack-Family Evaluation (Task 10)
    print("\n[9/10] Computing per-attack-family metrics and failure analysis...")
    test_families = prov_test["label_family"] if "label_family" in prov_test.columns else pd.Series(["UNKNOWN"] * len(y_test))
    per_family_rf = compute_per_family_metrics(y_test, rf_test, test_families, threshold=0.5)

    # Error analysis with difficult samples and provenance
    error_analysis = {
        "rf": compute_error_analysis(y_test, rf_test, threshold=0.5, features_df=test_df, duplicate_mask=split_result.test_duplicate_mask, provenance_df=prov_test),
        "per_family": per_family_rf,
    }
    if len(lstm_test) > 0 and fusion_test_series is not None:
        error_analysis["lstm"] = compute_error_analysis(y_test_seq, lstm_test, threshold=0.5, provenance_df=prov_test.iloc[lstm_test.index].reset_index(drop=True))
        error_analysis["fusion"] = compute_error_analysis(y_test_aligned, fusion_test_series, threshold=0.5, provenance_df=prov_test.iloc[aligned_test_rf.index].reset_index(drop=True))
        error_analysis["model_disagreements"] = analyze_model_disagreements(
            y_test_aligned, aligned_test_rf, aligned_test_lstm, fusion_score=fusion_test_series, threshold=0.5
        )

    # Calibration & Thresholding
    cal_rf = calibration_report(y_val, rf_val).to_dict()
    cal_lstm = calibration_report(y_val_seq, lstm_val).to_dict() if len(lstm_val) else None
    cal_fusion = None

    test_calibration: dict[str, Any] = {}
    try:
        platt_rf = PlattCalibrator().fit(y_val, rf_val)
        calibrated_test_rf = platt_rf.transform(rf_test)
        test_calibration["rf"] = calibration_report(y_test, calibrated_test_rf).to_dict()
    except Exception as exc:
        test_calibration["note"] = str(exc)

    eval_val_scores = rf_val if fusion_test_series is None else (alpha * aligned_val_rf + (1.0 - alpha) * aligned_val_lstm)
    eval_val_y = y_val if fusion_test_series is None else y_val_aligned
    val_sweep = threshold_sweep(eval_val_y, eval_val_scores)
    threshold_candidates = candidate_operating_points(val_sweep)

    # 10. TreeSHAP Feature Attributions (Task 21)
    shap_summary = None
    if not skip_shap and shap_cfg.get("enabled", True):
        print("\n[10/10] Computing TreeSHAP explainability...")
        try:
            shap_summary = compute_rf_shap_explanations(
                rf,
                X_background=X_train,
                X_explain=X_test,
                y_explain=y_test,
                families_explain=test_families,
                feature_names=feature_names,
                max_background=int(shap_cfg.get("max_background", 100)),
                max_explain=int(shap_cfg.get("max_explain", 200)),
                seed=seed,
            )
            print(f"        SHAP top feature: {shap_summary['global_importance'][0]['feature']} (mean |SHAP|={shap_summary['global_importance'][0]['mean_abs_shap']:.4f})")
        except Exception as exc:
            print(f"WARNING: SHAP computation failed: {exc}", file=sys.stderr)
    else:
        print("\n[10/10] Skipping SHAP computation.")

    # Cross-dataset transfer evaluation
    transfer_results = None
    if target_key:
        target_avail = dataset_availability(manifest, target_key)
        transfer_results = registry.transfer_compatibility_report(dataset_key, target_key, candidate_features=feature_names)
        transfer_results["target_availability"] = target_avail["status"]

    duration_s = time.time() - started_time

    # Profiling and Resource Check
    profiler.__exit__(None, None, None)
    resource_info = profiler.to_dict()
    peak_rss_gb = resource_info["peak_rss_mib"] / 1024.0
    if peak_rss_gb > max_memory_gb:
        raise MemoryError(
            f"Execution exceeded memory budget: peak RSS was {peak_rss_gb:.2f} GiB (limit {max_memory_gb:.2f} GiB)"
        )

    # Write all artifacts
    out_dir.mkdir(parents=True, exist_ok=True)
    population.write_manifest(out_dir / "experiment_population.json")
    (out_dir / "split_manifest.json").write_text(json.dumps(split_result.manifest, indent=2, default=str), encoding="utf-8")
    (out_dir / "leakage_report.json").write_text(json.dumps(split_result.leakage, indent=2, default=str), encoding="utf-8")
    (out_dir / "preprocessor_metadata.json").write_text(json.dumps(preprocessor.metadata(), indent=2, default=str), encoding="utf-8")
    (out_dir / "test_metrics.json").write_text(json.dumps({"native": native_metrics, "aligned": aligned_metrics}, indent=2, default=str), encoding="utf-8")
    (out_dir / "model_comparisons.json").write_text(json.dumps(statistical_comparisons, indent=2, default=str), encoding="utf-8")
    (out_dir / "error_analysis.json").write_text(json.dumps(error_analysis, indent=2, default=str), encoding="utf-8")
    (out_dir / "calibration_report.json").write_text(json.dumps({
        "validation_calibration": {"rf": cal_rf, "lstm": cal_lstm, "fusion": cal_fusion},
        "test_calibration": test_calibration,
    }, indent=2, default=str), encoding="utf-8")
    (out_dir / "threshold_candidates.json").write_text(json.dumps(threshold_candidates, indent=2, default=str), encoding="utf-8")
    (out_dir / "resource_profile.json").write_text(json.dumps(resource_info, indent=2), encoding="utf-8")

    # Export per-family metrics CSV
    if "summary_table" in per_family_rf:
        pd.DataFrame(per_family_rf["summary_table"]).to_csv(out_dir / "per_family_metrics.csv", index=False)

    if shap_summary is not None:
        (out_dir / "shap_summary.json").write_text(json.dumps(shap_summary, indent=2, default=str), encoding="utf-8")
    if transfer_results is not None:
        (out_dir / "transfer_report.json").write_text(json.dumps(transfer_results, indent=2, default=str), encoding="utf-8")

    # Save predictions
    preds_dict = {
        "true_label": y_test_aligned.to_numpy(),
        "majority_score": maj_test[aligned_idx],
        "lr_score": lr_test[aligned_idx],
        "dt_score": dt_test[aligned_idx],
        "rf_score": aligned_test_rf.to_numpy(),
    }
    if fusion_test_series is not None:
        preds_dict["lstm_score"] = aligned_test_lstm.to_numpy()
        preds_dict["fusion_score"] = fusion_test_series.to_numpy()
    pd.DataFrame(preds_dict, index=y_test_aligned.index).to_csv(out_dir / "predictions_test.csv", index=True)

    # Save models
    rf.save(out_dir)
    dt.save(out_dir)
    lr.save(out_dir)
    maj.save(out_dir)
    if lstm is not None:
        lstm.save(out_dir)
    preprocessor.save(out_dir)

    # Build and write experiment record
    exp_status = "PRELIMINARY_SUBSAMPLE" if pop_config.sample_limit else "EMPIRICALLY_OBSERVED"
    record = ExperimentRecord(
        experiment_id=exp_cfg.get("id", f"EXP-P1-{dataset_key.upper()}-{int(time.time())}"),
        research_question=exp_cfg.get("research_question", "RQ1_RQ2"),
        hypothesis=exp_cfg.get("hypothesis", ""),
        dataset=dataset_key,
        dataset_sha256=population.files[0].sha256 if population.files else None,
        dataset_version="1.0.0",
        input_files=[f.filename for f in population.files],
        rows_total=len(population.features),
        rows_train=len(train_df),
        rows_validation=len(val_df),
        rows_test=len(test_df),
        feature_contract=rung,
        feature_list=feature_names,
        feature_schema_hash=registry.schema_hash(rung),
        preprocessing=preprocessor.metadata(),
        split_id=split_result.manifest.get("split_config_hash"),
        model=rf.config(),
        hyperparameters={"rf": rf_params, "split": split_cfg, "duplicate_policy": dup_policy},
        random_seed=seed,
        threshold=0.5,
        threshold_decision_id="D-003",
        metrics={"native": native_metrics, "aligned": aligned_metrics},
        confusion_matrix=aligned_metrics["models"]["random_forest"]["confusion"],
        training_duration_s=duration_s,
        hardware=f"CPU ({resource_info.get('cpu_count', 1)} cores)",
        resource_profile=resource_info,
        status=exp_status,
        result_interpretation=(
            "Preliminary validation run on subsampled data." if pop_config.sample_limit
            else "Multi-file empirical research evaluation on full verified dataset population."
        ),
        limitations=[
            "Threshold objective D-003 remains open; reporting uses neutral threshold 0.5.",
            "Feature contract candidate evaluation.",
            f"Duplicate policy applied: {dup_policy}.",
        ],
        artifacts={
            "population_manifest": str(out_dir / "experiment_population.json"),
            "predictions": str(out_dir / "predictions_test.csv"),
            "per_family_metrics": str(out_dir / "per_family_metrics.csv"),
            "card": str(out_dir / "experiment_card.md"),
        },
        git_commit=git_commit(),
        software_environment=environment_fingerprint(),
    )
    write_experiment_record(record, out_dir / "experiment_record.json")

    # Generate full self-contained Experiment Card
    card_md = generate_experiment_card(
        record,
        population,
        baseline_metrics=native_metrics,
        aligned_metrics=aligned_metrics,
        statistical_comparisons=statistical_comparisons,
        per_family_metrics=per_family_rf,
        calibration_data={"validation_calibration": {"rf": cal_rf, "lstm": cal_lstm, "fusion": cal_fusion}, "test_calibration": test_calibration},
        threshold_data=threshold_candidates,
        error_analysis=error_analysis,
        shap_data=shap_summary,
        transfer_data=transfer_results,
    )
    (out_dir / "experiment_card.md").write_text(card_md, encoding="utf-8")
    (out_dir / "experiment_report.md").write_text(card_md, encoding="utf-8")

    return {
        "seed": seed,
        "record": record,
        "native_metrics": native_metrics,
        "aligned_metrics": aligned_metrics,
        "statistical_comparisons": statistical_comparisons,
        "duration_s": duration_s,
    }


def run_experiment(
    config_path: str | Path,
    *,
    sample_limit: int | None = None,
    out_dir: str | Path | None = None,
    skip_shap: bool = False,
    skip_lstm: bool = False,
    transfer_target: str | None = None,
    seeds: list[int] | None = None,
    max_memory_gb: float = 10.0,
) -> int:
    """Entry point supporting single or multi-seed research runs."""
    config = load_yaml_config(config_path)
    split_cfg = config.get("split", {})
    exp_cfg = config.get("experiment", {})
    dataset_cfg = config.get("dataset", {})
    dataset_key = dataset_cfg.get("key", "dataset")

    run_seeds = seeds or split_cfg.get("seeds") or [int(split_cfg.get("seed", 42))]

    base_exp_id = exp_cfg.get("id", f"EXP-P1-{dataset_key.upper()}-{int(time.time())}")
    base_out_dir = Path(out_dir or config.get("outputs", {}).get("results_dir", f"results/experiments/{base_exp_id}"))

    print(f"\n================================================================================")
    print(f"Launching Experiment: {base_exp_id} (Dataset: {dataset_key}, Seeds: {run_seeds})")
    print(f"================================================================================")

    multi_results: list[dict[str, Any]] = []

    for idx, s in enumerate(run_seeds):
        target_dir = base_out_dir if len(run_seeds) == 1 else (base_out_dir / f"seed_{s}")
        print(f"\n--- Running Seed [{idx+1}/{len(run_seeds)}]: seed={s} -> {target_dir}/ ---")
        res = run_experiment_pipeline(
            config,
            s,
            sample_limit=sample_limit,
            out_dir=target_dir,
            skip_shap=skip_shap,
            skip_lstm=skip_lstm,
            transfer_target=transfer_target,
            max_memory_gb=max_memory_gb,
        )
        multi_results.append(res)

    if len(run_seeds) > 1:
        # Aggregate multi-seed metrics
        rf_aligned_per_seed = [r["aligned_metrics"]["models"]["random_forest"] for r in multi_results]
        rf_summary = multi_seed_summary(rf_aligned_per_seed)
        multi_manifest = {
            "seeds": run_seeds,
            "random_forest_aligned_summary": rf_summary,
        }
        (base_out_dir / "multi_seed_summary.json").write_text(json.dumps(multi_manifest, indent=2), encoding="utf-8")
        print(f"\nMulti-seed evaluation complete across {len(run_seeds)} seeds:")
        print(f"Random Forest Aligned F1: {rf_summary.get('f1', {}).get('mean', 'N/A')} ± {rf_summary.get('f1', {}).get('std', 'N/A')}")
        print(f"Summary: {base_out_dir / 'multi_seed_summary.json'}")

    print(f"\nAll experiment stages completed successfully!")
    print(f"Experiment Card: {base_out_dir / 'experiment_card.md'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 1 Multi-File Research Experiment Runner")
    parser.add_argument("--config", required=True, help="Path to YAML experiment configuration")
    parser.add_argument("--sample-limit", type=int, default=None, help="Optional row subsample limit for development/debugging")
    parser.add_argument("--out-dir", default=None, help="Optional custom output directory")
    parser.add_argument("--skip-shap", action="store_true", help="Skip SHAP computation")
    parser.add_argument("--skip-lstm", action="store_true", help="Skip Supervised LSTM training")
    parser.add_argument("--transfer-target", default=None, help="Target dataset for cross-dataset transfer evaluation")
    parser.add_argument("--seeds", type=int, nargs="+", default=None, help="Optional list of random seeds for robustness evaluation")
    parser.add_argument("--max-memory-gb", type=float, default=10.0, help="Maximum allowed peak RSS memory budget in GiB (default: 10.0)")
    args = parser.parse_args()

    return run_experiment(
        args.config,
        sample_limit=args.sample_limit,
        out_dir=args.out_dir,
        skip_shap=args.skip_shap,
        skip_lstm=args.skip_lstm,
        transfer_target=args.transfer_target,
        seeds=args.seeds,
        max_memory_gb=args.max_memory_gb,
    )


if __name__ == "__main__":
    raise SystemExit(main())
