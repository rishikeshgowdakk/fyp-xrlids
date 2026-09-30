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

from xrlids.evaluation.calibration import calibration_report
from xrlids.evaluation.metrics import evaluate
from xrlids.evaluation.thresholding import candidate_operating_points, threshold_sweep
from xrlids.experiments.registry import ExperimentRecord, make_experiment_id
from xrlids.features.registry import FeatureRegistry
from xrlids.labels.contract import LabelContract
from xrlids.models.lstm import LSTMDetector, assert_no_boundary_crossing, build_sequences
from xrlids.models.random_forest import RandomForestDetector
from xrlids.models.fusion import align_scores, fuse_scores
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
    semantics_available = registry.available_semantics(dataset)
    from xrlids.features.compute import compute_features, extract_semantics, validate_feature_matrix

    semantics, extraction_report = extract_semantics(cleaned.frame, dataset, registry, strict=True)
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
    split_config = SplitConfig(seed=seed, methodology="stratified_random", rationale="random stratified split; no timestamp/group column assumed for this dataset")
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
    fusion_val = fuse_scores(aligned_val_rf, aligned_val_lstm, alpha=0.5, how="strict")

    aligned_test_rf, aligned_test_lstm, align_test = align_scores(rf_test, lstm_test, how="inner")
    y_test_aligned = pd.Series(y_test.to_numpy()[aligned_test_rf.index], index=aligned_test_rf.index)
    fusion_test = fuse_scores(aligned_test_rf, aligned_test_lstm, alpha=0.5, how="strict")
    test_fusion = evaluate(y_test_aligned, fusion_test.scores, 0.5)

    # ---- 8. threshold sweep + candidates (VALIDATION only) --------------------
    sweep = threshold_sweep(y_val_aligned, fusion_val.scores)
    candidates = candidate_operating_points(sweep)

    # ---- 9. calibration on VALIDATION -----------------------------------------
    cal_rf = calibration_report(y_val, rf_val).to_dict()
    cal_lstm = calibration_report(y_val_seq, lstm_val).to_dict() if len(lstm_val) else None
    cal_fusion = calibration_report(y_val_aligned, fusion_val.scores).to_dict()

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
        "rf_feature_importance": rf.feature_importances().to_dict(orient="records"),
        "threshold_used_for_reporting": 0.5,
        "threshold_note": (
            "0.5 is a neutral reporting point only. The operating objective is D-003 and "
            "remains OPEN; no threshold has been frozen."
        ),
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
    )
