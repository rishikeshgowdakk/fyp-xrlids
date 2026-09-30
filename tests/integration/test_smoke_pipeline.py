"""Integration test: the full Phase 1 chain on a synthetic fixture.

This validates plumbing, provenance and guard-rails. It does NOT validate detection
performance: the fixture is synthetic and its metrics are meaningless by construction.
"""

from __future__ import annotations

import pandas as pd
import pytest

from xrlids.pipeline import run_single_dataset
from xrlids.testing import synthetic_cic_frame


@pytest.fixture(scope="module")
def result(registry, contract):
    frame = synthetic_cic_frame(n_rows=600, seed=3)
    return run_single_dataset(
        frame,
        dataset="cicids2017",
        rung="R10",
        contract=contract,
        registry=registry,
        seq_len=5,
        seed=3,
        lstm_params={"epochs": 2, "patience": 2, "batch_size": 64, "hidden_size": 8, "num_layers": 1, "dropout": 0.0},
        smoke=True,
    )


def test_pipeline_completes_and_is_labelled_smoke(result):
    assert result.status == "SMOKE_ONLY"
    assert "SMOKE" in result.payload["smoke_test"]


def test_required_result_sections_present(result):
    p = result.payload
    for key in [
        "label_audit", "cleaning", "feature_contract", "split_manifest", "leakage_audit",
        "preprocessing", "model_rf", "model_lstm", "population", "test_metrics",
        "threshold_candidates", "calibration",
    ]:
        assert key in p, key


def test_cleaning_accounting_reconciles(result):
    acc = result.payload["cleaning"]
    assert acc["raw_rows_at_start"] - acc["total_removed"] == acc["final_accepted_rows"]


def test_leakage_audit_passed_on_fixture(result):
    assert result.payload["leakage_audit"]["status"] == "pass"


def test_threshold_decision_is_marked_open(result):
    candidates = result.payload["threshold_candidates"]
    assert candidates["decision_id"] == "D-003"
    assert "OPEN" in candidates["decision_status"]
    assert set(candidates["candidates"]) == {
        "max_f1", "min_fpr_subject_to_recall_floor", "min_fnr_subject_to_fpr_ceiling", "cost_sensitive"
    }


def test_evaluation_populations_are_explicit(result):
    pop = result.payload["population"]
    assert pop["fusion_aligned_test_rows"] <= pop["test_rows_scored_by_rf"]
    assert "fusion_alignment" in pop


def test_metrics_reported_with_threshold_and_population(result):
    metrics = result.payload["test_metrics"]
    for model in ("rf", "lstm", "fusion"):
        assert metrics[model]["threshold"] == 0.5
        assert metrics[model]["population"] > 0
        assert "confusion" in metrics[model]


def test_preprocessing_fit_only_on_train(result):
    meta = result.payload["preprocessing"]
    train_rows = result.payload["population"]["train_rows"]
    assert meta["n_train_rows"] == train_rows


def test_unsw_r10_is_blocked_not_faked(registry, contract):
    frame = synthetic_cic_frame(n_rows=120, seed=1)
    res = run_single_dataset(
        frame, dataset="unsw_nb15", rung="R10", contract=contract, registry=registry, seed=1
    )
    assert res.status == "BLOCKED_FEATURE_INCOMPATIBLE"
    assert res.payload["feature_contract"]["unavailable"]
    assert "test_metrics" not in res.payload
    assert any("compatibility" in w.lower() or "cannot supply" in w.lower() for w in res.warnings)
