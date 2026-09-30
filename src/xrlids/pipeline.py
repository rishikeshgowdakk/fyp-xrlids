"""Single-dataset Phase 1 orchestration.

Runs the full chain for one dataset and one feature rung:

    clean -> features -> split -> leakage audit -> preprocess (train-only fit)
          -> RF -> LSTM -> aligned comparison -> fusion
          -> metrics -> threshold sweep (candidates only) -> calibration

The function is deliberately explicit about what it does NOT do: it does not select an
operating threshold (D-003 is open) and it reports the evaluation population for every
number.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from xrlids.evaluation.calibration import PlattCalibrator, calibration_report
from xrlids.evaluation.error_analysis import (
    analyze_model_disagreements,
    compute_error_analysis,
)
from xrlids.evaluation.metrics import evaluate
from xrlids.evaluation.thresholding import candidate_operating_points, threshold_sweep
from xrlids.experiments.registry import ExperimentRecord, make_experiment_id
from xrlids.explainability.shap_analysis import compute_rf_shap_explanations
from xrlids.features.registry import FeatureRegistry
from xrlids.labels.contract import LabelContract
from xrlids.models.lstm import LSTMDetector, assert_no_boundary_crossing, build_sequences
from xrlids.models.random_forest import RandomForestDetector
from xrlids.models.fusion import align_scores, fuse_scores, tune_fusion_alpha
from xrlids.preprocessing.cleaning import clean_dataset_frame
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.splitting.splitter import SplitConfig, build_splits
from xrlids.utils.logging_utils import get_logger
from xrlids.utils.seeding import set_global_seeds

logger = get_logger(__name__)

SMOKE_NOTE = (
    "SMOKE TEST - executed on synthetic fixtures, NOT a dataset result and NOT evidence."
)


@dataclass
class PipelineResult:
    dataset: str
    rung: str
    status: str
    experiment_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    models: dict[str, Any] = field(default_factory=dict, repr=False)
    preprocessor: Any = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "rung": self.rung,
            "status": self.status,
            "experiment_id": self.experiment_id,
            "warnings": self.warnings,
            **self.payload,
        }


def run_single_dataset(
    raw_frame: pd.DataFrame,
    *,
    dataset: str,
    rung: str,
    contract: LabelContract,
    registry: FeatureRegistry,
    seq_len: int = 5,
    seed: int = 42,
    rf_params: dict[str, Any] | None = None,
    lstm_params: dict[str, Any] | None = None,
    smoke: bool = False,
    sequence: int = 1,
    duplicate_policy: str = "deduplicate_features",
    split_config: SplitConfig | None = None,
    tune_alpha: bool = True,
    run_shap: bool = False,
    save_artifacts_dir: str | Path | None = None,
) -> PipelineResult:
    """Execute the Phase 1 chain for one dataset/rung pair."""
    set_global_seeds(seed)
    warnings: list[str] = []
    started = time.time()

    features = registry.rung_features(rung)
    unsupported = registry.unsupported_features(dataset, rung)
    if unsupported:
        warnings.append(
            f"dataset '{dataset}' cannot supply {len(unsupported)}/{len(features)} features of "
            f"{rung}: {unsupported}. Feature contract compatibility issue - see FEATURE_COMPATIBILITY.md."
        )

    # ---- 1. cleaning + labels -------------------------------------------------
    cleaned = clean_dataset_frame(raw_frame, dataset, contract)
    labels = cleaned.labels.binary
    accepted_index = cleaned.frame.index

    # ---- 2. features ----------------------------------------------------------
    from xrlids.features.compute import (
        FeatureValidationError,
        compute_features,
        extract_semantics,
    )

    try:
        semantics, extraction_report = extract_semantics(cleaned.frame, dataset, registry, strict=True)
    except FeatureValidationError as exc:
        # The dataset cannot even supply the semantic fields this contract needs. Report it
        # as blocked rather than crashing or substituting columns (section 39: fail loudly,
        # but do not fabricate a way forward).
        return PipelineResult(
            dataset=dataset,
            rung=rung,
            status="BLOCKED_FEATURE_INCOMPATIBLE",
            experiment_id=make_experiment_id(
                phase=1, model="MULTI", dataset=dataset, rung=rung, sequence=sequence
            ),
            warnings=warnings + [str(exc)],
            payload={
                "feature_contract": {
                    "rung": rung,
                    "available": registry.features_supported(dataset, rung),
                    "unavailable": unsupported,
                },
                "note": (
                    "experiment not executed: the dataset's raw columns cannot satisfy the "
                    "semantic fields required by this feature contract"
                ),
                "extraction_error": str(exc),
            },
        )

    feature_frame, available, unavailable = compute_features(
        semantics, features, dataset=dataset, strict=False
    )
    if unavailable:
        warnings.append(f"features not computable for '{dataset}': {unavailable}")

    # A row is usable only if every rung feature is finite; otherwise the row would carry
    # imputed noise. The count is reported, not silently dropped.
    finite_mask = np.isfinite(feature_frame[available].to_numpy(dtype=float)).all(axis=1)
    rows_dropped_nonfinite = int((~finite_mask).sum())
    feature_frame = feature_frame.loc[finite_mask].reset_index(drop=True)
    labels = labels.loc[finite_mask].reset_index(drop=True)
    cleaned_frame = cleaned.frame.loc[finite_mask].reset_index(drop=True)

    if rows_dropped_nonfinite:
        warnings.append(
            f"{rows_dropped_nonfinite} rows dropped because a rung feature was non-finite "
            "(e.g. zero-duration flow with non-zero packets); see DATA_CLEANING_POLICY.md"
        )

    if len(available) < len(features):
        return PipelineResult(
            dataset=dataset,
            rung=rung,
            status="BLOCKED_FEATURE_INCOMPATIBLE",
            experiment_id=make_experiment_id(
                phase=1,
                model="MULTI",
                dataset=dataset,
                rung=rung,
                sequence=sequence,
            ),
            warnings=warnings,
            payload={
                "feature_contract": {"rung": rung, "available": available, "unavailable": unavailable},
                "note": "experiment not executed: the feature contract cannot be satisfied for this dataset",
            },
        )

    # ---- 3. splits + leakage ---------------------------------------------------
    if split_config is None:
        split_config = SplitConfig(
            seed=seed,
            methodology="stratified_random",
            rationale="random stratified split; no timestamp/group column assumed for this dataset",
            duplicate_policy=duplicate_policy,
        )
    split_result = build_splits(feature_frame, labels, available, split_config, dataset=dataset)
    train = split_result.splits["train"]
    validation = split_result.splits["validation"]
    test = split_result.splits["test"]
    y_train = labels.loc[split_result.assignment == "train"].reset_index(drop=True)
    y_val = labels.loc[split_result.assignment == "validation"].reset_index(drop=True)
    y_test = labels.loc[split_result.assignment == "test"].reset_index(drop=True)

    # ---- 4. preprocessing (fit on train ONLY) ---------------------------------
    preprocessor = Preprocessor(features=available, dataset=dataset).fit(train)
    X_train = preprocessor.transform(train)
    X_val = preprocessor.transform(validation)
    X_test = preprocessor.transform(test)

    # ---- 5. Random Forest ------------------------------------------------------
    rf = RandomForestDetector(params=rf_params or {}, feature_names=available).fit(X_train, y_train)
    rf_val = pd.Series(rf.predict_proba(X_val), index=X_val.index, name="rf_score")
    rf_test = pd.Series(rf.predict_proba(X_test), index=X_test.index, name="rf_score")

    # ---- 6. LSTM ---------------------------------------------------------------
    train_seqs = build_sequences(X_train, y_train, split="train", seq_len=seq_len)
    val_seqs = build_sequences(X_val, y_val, split="validation", seq_len=seq_len)
    test_seqs = build_sequences(X_test, y_test, split="test", seq_len=seq_len)
    assert_no_boundary_crossing(
        [train_seqs, val_seqs, test_seqs],
        {"train": len(X_train), "validation": len(X_val), "test": len(X_test)},
    )

    lstm = LSTMDetector(params=lstm_params or {}, feature_names=available, seq_len=seq_len, seed=seed)
    lstm.fit(train_seqs, val_seqs)
    lstm_val_scores = lstm.predict_proba(val_seqs)
    lstm_test_scores = lstm.predict_proba(test_seqs)

    # LSTM produces one score per sequence; attribute it to the final element's row so the
    # evaluation population is explicit rather than implied.
    lstm_val = pd.Series(lstm_val_scores, index=val_seqs.origins + seq_len - 1, name="lstm_score")
    lstm_test = pd.Series(lstm_test_scores, index=test_seqs.origins + seq_len - 1, name="lstm_score")
    y_val_seq = pd.Series(y_val.to_numpy()[lstm_val.index], index=lstm_val.index)
    y_test_seq = pd.Series(y_test.to_numpy()[lstm_test.index], index=lstm_test.index)

    # ---- 7. metrics on the untouched TEST population ---------------------------
    # Threshold 0.5 is used only as a neutral reporting point; D-003 remains open.
    test_rf = evaluate(y_test, rf_test, 0.5)
    test_lstm = evaluate(y_test_seq, lstm_test, 0.5)

    aligned_val_rf, aligned_val_lstm, align_val = align_scores(rf_val, lstm_val, how="inner")
    y_val_aligned = pd.Series(y_val.to_numpy()[aligned_val_rf.index], index=aligned_val_rf.index)

    # Alpha selection: tune on validation or use default 0.5
    fusion_tuning = None
    alpha = 0.5
    if tune_alpha and len(aligned_val_rf) > 0 and y_val_aligned.nunique() >= 2:
        fusion_tuning = tune_fusion_alpha(aligned_val_rf, aligned_val_lstm, y_val_aligned, metric="roc_auc")
        alpha = fusion_tuning["best_alpha"]

    fusion_val = fuse_scores(aligned_val_rf, aligned_val_lstm, alpha=alpha, how="strict")

    aligned_test_rf, aligned_test_lstm, align_test = align_scores(rf_test, lstm_test, how="inner")
    y_test_aligned = pd.Series(y_test.to_numpy()[aligned_test_rf.index], index=aligned_test_rf.index)
    fusion_test = fuse_scores(aligned_test_rf, aligned_test_lstm, alpha=alpha, how="strict")
    test_fusion = evaluate(y_test_aligned, fusion_test.scores, 0.5)

    # ---- 8. threshold sweep + candidates (VALIDATION only) --------------------
    sweep = threshold_sweep(y_val_aligned, fusion_val.scores)
    candidates = candidate_operating_points(sweep)

    # ---- 9. calibration (fit on VALIDATION only, evaluate on test) ------------
    cal_rf = calibration_report(y_val, rf_val).to_dict()
    cal_lstm = calibration_report(y_val_seq, lstm_val).to_dict() if len(lstm_val) else None
    cal_fusion = calibration_report(y_val_aligned, fusion_val.scores).to_dict()

    test_calibration: dict[str, Any] = {}
    try:
        platt_rf = PlattCalibrator().fit(y_val, rf_val)
        calibrated_test_rf = platt_rf.transform(rf_test)
        test_calibration["rf"] = calibration_report(y_test, calibrated_test_rf).to_dict()

        platt_fusion = PlattCalibrator().fit(y_val_aligned, fusion_val.scores)
        calibrated_test_fusion = platt_fusion.transform(fusion_test.scores)
        test_calibration["fusion"] = calibration_report(y_test_aligned, calibrated_test_fusion).to_dict()
    except Exception as exc:
        test_calibration["note"] = f"test calibration skipped: {exc}"

    # ---- 10. error analysis (deterministic) -----------------------------------
    dupe_mask_test = split_result.test_duplicate_mask
    error_rf = compute_error_analysis(
        y_test, rf_test, threshold=0.5, features_df=test, duplicate_mask=dupe_mask_test
    )
    error_lstm = compute_error_analysis(
        y_test_seq, lstm_test, threshold=0.5
    )
    aligned_dupe_mask = dupe_mask_test.iloc[aligned_test_rf.index].reset_index(drop=True) if dupe_mask_test is not None else None
    error_fusion = compute_error_analysis(
        y_test_aligned, fusion_test.scores, threshold=0.5, duplicate_mask=aligned_dupe_mask
    )
    model_disagreements = analyze_model_disagreements(
        y_test_aligned, aligned_test_rf, aligned_test_lstm, fusion_score=fusion_test.scores, threshold=0.5
    )

    # ---- 11. SHAP analysis (TreeSHAP on Random Forest) ------------------------
    shap_summary: dict[str, Any] | None = None
    if run_shap:
        try:
            shap_summary = compute_rf_shap_explanations(
                rf,
                X_background=X_train,
                X_explain=X_test,
                y_explain=y_test,
                feature_names=available,
                max_background=100,
                max_explain=200,
                seed=seed,
            )
        except Exception as exc:
            warnings.append(f"SHAP explanation failed: {exc}")

    # ---- 12. Artifact saving (if path provided) -------------------------------
    saved_artifacts: dict[str, str] = {}
    if save_artifacts_dir:
        out_p = Path(save_artifacts_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        rf_path = rf.save(out_p)
        lstm_path = lstm.save(out_p)
        preproc_path = preprocessor.save(out_p)
        saved_artifacts["rf_model"] = str(rf_path)
        saved_artifacts["lstm_model"] = str(lstm_path)
        saved_artifacts["preprocessor"] = str(preproc_path)

        # Save test predictions DataFrame
        preds_df = pd.DataFrame({
            "true_label": y_test_aligned.to_numpy(),
            "rf_score": aligned_test_rf.to_numpy(),
            "lstm_score": aligned_test_lstm.to_numpy(),
            "fusion_score": fusion_test.scores,
        }, index=aligned_test_rf.index)
        preds_file = out_p / "predictions_aligned_test.csv"
        preds_df.to_csv(preds_file, index=True)
        saved_artifacts["predictions_test"] = str(preds_file)

    elapsed = time.time() - started

    payload: dict[str, Any] = {
        "label_audit": cleaned.labels.stats,
        "cleaning": cleaned.accounting,
        "cleaning_steps": [s.to_dict() for s in cleaned.steps],
        "feature_contract": {"rung": rung, "available": available, "unavailable": unavailable},
        "feature_extraction": extraction_report,
        "split_manifest": split_result.manifest,
        "leakage_audit": split_result.leakage,
        "preprocessing": preprocessor.metadata(),
        "model_rf": rf.config(),
        "model_lstm": lstm.config(),
        "fusion_tuning": fusion_tuning,
        "population": {
            "train_rows": int(len(train)),
            "validation_rows": int(len(validation)),
            "test_rows": int(len(test)),
            "test_rows_scored_by_rf": int(len(rf_test)),
            "test_sequences_scored_by_lstm": int(len(lstm_test)),
            "fusion_aligned_test_rows": int(len(aligned_test_rf)),
            "fusion_alignment": align_test,
            "validation_fusion_alignment": align_val,
        },
        "test_metrics": {
            "rf": test_rf,
            "lstm": test_lstm,
            "fusion": test_fusion,
        },
        "validation_threshold_sweep": sweep.to_dict(orient="records"),
        "threshold_candidates": candidates,
        "calibration": {"rf": cal_rf, "lstm": cal_lstm, "fusion": cal_fusion},
        "test_calibration": test_calibration,
        "error_analysis": {
            "rf": error_rf,
            "lstm": error_lstm,
            "fusion": error_fusion,
            "model_disagreements": model_disagreements,
        },
        "shap_analysis": shap_summary,
        "rf_feature_importance": rf.feature_importances().to_dict(orient="records"),
        "threshold_used_for_reporting": 0.5,
        "threshold_note": (
            "0.5 is a neutral reporting point only. The operating objective is D-003 and "
            "remains OPEN; no threshold has been frozen."
        ),
        "saved_artifacts": saved_artifacts,
        "training_duration_s": elapsed,
        "data_provenance": {"source": "synthetic_fixture" if smoke else "dataset_file"},
    }
    if smoke:
        payload["smoke_test"] = SMOKE_NOTE

    experiment_id = make_experiment_id(
        phase=1,
        model="MULTI",
        dataset=dataset,
        rung=rung,
        sequence=sequence,
    )
    return PipelineResult(
        dataset=dataset,
        rung=rung,
        status="SMOKE_ONLY" if smoke else "EXECUTED",
        experiment_id=experiment_id,
        payload=payload,
        warnings=warnings,
        models={"rf": rf, "lstm": lstm},
        preprocessor=preprocessor,
    )
