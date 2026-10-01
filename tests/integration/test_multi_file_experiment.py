"""Integration test: multi-file research experiment engine (Tasks 1-27)."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
import yaml

from scripts.phase1.run_experiment import run_experiment


def test_multi_file_experiment_execution(tmp_path):
    # Create test experiment config using real verified UNSW files with sample limit
    exp_dir = tmp_path / "test_exp"
    config_dict = {
        "experiment": {
            "id": "TEST-EXP-UNSW-001",
            "phase": 1,
            "research_question": "RQ1_TEST",
            "hypothesis": "Test multi-file research engine on verified files.",
            "status": "ready_for_execution",
        },
        "dataset": {
            "key": "unsw_nb15",
            "files": ["UNSW_NB15_testing-set.csv", "UNSW_NB15_training-set.csv"],
            "require_verified_checksums": True,
            "require_schema_validated": True,
        },
        "label_contract": {
            "path": "configs/labels/label_mapping.yaml",
            "require_status": "candidate_frozen",
            "unknown_label_policy": "REJECT",
        },
        "features": {
            "registry": "configs/features/features.yaml",
            "mode": "programmatic_common_transfer_contract",
            "rung": "R10",
            "require_frozen": False,
        },
        "target_dataset": {
            "key": "cse_cic_ids2018",
        },
        "cleaning": {
            "drop_exact_duplicates": True,
            "drop_negative_duration": True,
            "accounting_required": True,
        },
        "split": {
            "methodology": "stratified_random",
            "duplicate_policy": "deduplicate_features",
            "duplicate_conflict_policy": "reject_conflicts",
            "train": 0.6,
            "validation": 0.2,
            "test": 0.2,
            "seed": 42,
            "leakage_audit_required": True,
            "fail_on_leakage": True,
        },
        "preprocessing": {
            "scaler": "StandardScaler",
            "imputation": "median_train",
            "fit_on": "train_only",
        },
        "models": {
            "random_forest": {
                "n_estimators": 10,
                "max_depth": 8,
                "random_state": 42,
            },
        },
        "outputs": {
            "results_dir": str(exp_dir),
            "save_models": True,
        },
    }

    config_path = tmp_path / "test_exp_config.yaml"
    config_path.write_text(yaml.safe_dump(config_dict), encoding="utf-8")

    # Run experiment with small developmental sample_limit
    ret = run_experiment(
        config_path,
        sample_limit=200,
        out_dir=exp_dir,
        skip_shap=True,
        skip_lstm=True,
    )
    assert ret == 0

    # 1. Verify population manifest
    pop_manifest_path = exp_dir / "experiment_population.json"
    assert pop_manifest_path.is_file()
    pop_data = json.loads(pop_manifest_path.read_text(encoding="utf-8"))
    assert pop_data["dataset"] == "unsw_nb15"
    assert len(pop_data["files"]) == 2
    assert "accounting" in pop_data
    assert "duplicate_conflict_analysis" in pop_data

    # 2. Verify baseline ladder test metrics
    metrics_path = exp_dir / "test_metrics.json"
    assert metrics_path.is_file()
    metrics_data = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert "native" in metrics_data
    assert "aligned" in metrics_data
    for m in ["majority", "logistic_regression", "decision_tree", "random_forest"]:
        assert m in metrics_data["aligned"]["models"]
        assert "accuracy" in metrics_data["aligned"]["models"][m]
        assert "f1" in metrics_data["aligned"]["models"][m]

    # 3. Verify statistical model comparisons
    comp_path = exp_dir / "model_comparisons.json"
    assert comp_path.is_file()
    comp_data = json.loads(comp_path.read_text(encoding="utf-8"))
    assert len(comp_data) >= 2
    assert "delta" in comp_data[0]
    assert "p_value" in comp_data[0]
    assert "is_statistically_significant" in comp_data[0]

    # 4. Verify per-family metrics
    per_fam_csv = exp_dir / "per_family_metrics.csv"
    assert per_fam_csv.is_file()

    # 5. Verify resource profile
    res_path = exp_dir / "resource_profile.json"
    assert res_path.is_file()
    res_data = json.loads(res_path.read_text(encoding="utf-8"))
    assert "peak_rss_mib" in res_data
    assert res_data["peak_rss_mib"] > 0

    # 6. Verify self-contained experiment card
    card_path = exp_dir / "experiment_card.md"
    assert card_path.is_file()
    card_text = card_path.read_text(encoding="utf-8")
    assert "EXPERIMENT CARD: `TEST-EXP-UNSW-001`" in card_text
    assert "Multi-Stage Row Accounting" in card_text
    assert "Baseline Ladder Comparison" in card_text
    assert "Per-Attack-Family Evaluation" in card_text
