"""Integration tests verifying cross-dataset transfer artifacts and scientific isolation (Task 4)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from xrlids.features.registry import load_feature_registry

TRANSFER_EXPERIMENT_IDS = [
    "EXP-P1-TRANSFER-CIC-TO-CSE-R10-001",
    "EXP-P1-TRANSFER-CSE-TO-CIC-R10-001",
    "EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001",
    "EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001",
    "EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001",
    "EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001",
]


@pytest.mark.parametrize("exp_id", TRANSFER_EXPERIMENT_IDS)
def test_transfer_experiment_artifacts_exist_and_valid(exp_id: str):
    """Verify all machine-readable transfer artifacts exist and satisfy schema integrity."""
    exp_dir = Path("results/experiments") / exp_id
    assert exp_dir.is_dir(), f"Experiment directory {exp_id} does not exist"

    required_files = [
        "experiment_record.json",
        "experiment_record.json.meta.json",
        "test_metrics.json",
        "transfer_comparison.json",
        "distribution_shift.json",
        "error_analysis.json",
        "resource_profile.json",
        "experiment_card.md",
        "experiment_report.md",
    ]

    for fname in required_files:
        fpath = exp_dir / fname
        assert fpath.is_file(), f"{exp_id} is missing {fname}"
        assert fpath.stat().st_size > 0, f"{exp_id}/{fname} is empty"

    # Validate experiment_record.json
    with open(exp_dir / "experiment_record.json", encoding="utf-8") as f:
        rec = json.load(f)

    assert rec["experiment_id"] == exp_id
    assert rec["research_question"] == "RQ5_CROSS_DATASET_TRANSFER"
    assert rec["status"] == "EMPIRICALLY_OBSERVED"
    assert rec["preprocessing"]["fit_on"] == "source_train_only"

    # Validate test_metrics.json
    with open(exp_dir / "test_metrics.json", encoding="utf-8") as f:
        tm = json.load(f)

    assert "aligned" in tm
    models_dict = tm["aligned"].get("models", tm["aligned"])
    for m in ("majority", "logistic_regression", "decision_tree", "rf", "lstm", "fusion"):
        assert m in models_dict
        assert "f1" in models_dict[m]
        assert "accuracy" in models_dict[m]
        assert "fpr" in models_dict[m]

    # Validate transfer_comparison.json
    with open(exp_dir / "transfer_comparison.json", encoding="utf-8") as f:
        comp = json.load(f)

    assert isinstance(comp, list)
    assert len(comp) >= 6
    for row in comp:
        assert "source_f1" in row
        assert "transfer_f1" in row
        assert "delta_f1" in row
        assert round(row["transfer_f1"] - row["source_f1"], 4) == round(row["delta_f1"], 4)

    # Validate distribution_shift.json
    with open(exp_dir / "distribution_shift.json", encoding="utf-8") as f:
        shift = json.load(f)

    assert "features" in shift
    assert "label_distribution" in shift
    assert "class_prevalence_shift" in shift["label_distribution"]


def test_transfer_feature_contract_integrity():
    """Verify that primary transfer uses 10 features and UNSW auxiliary uses 4 features."""
    registry = load_feature_registry()

    # Primary 10-feature intersection between CIC and CSE
    r10_common = registry.common_transfer_contract("cicids2017", "cse_cic_ids2018", candidate_features="R10")
    assert len(r10_common) == 10
    assert "syn_count" in r10_common
    assert "packet_length_std" in r10_common

    # Auxiliary 4-feature intersection involving UNSW
    r4_cic_unsw = registry.common_transfer_contract("cicids2017", "unsw_nb15", candidate_features="R10")
    assert len(r4_cic_unsw) == 4
    assert r4_cic_unsw == ["flow_duration_ms", "flow_packets_per_s", "flow_bytes_per_s", "packet_length_mean"]

    r4_cse_unsw = registry.common_transfer_contract("cse_cic_ids2018", "unsw_nb15", candidate_features="R10")
    assert len(r4_cse_unsw) == 4
    assert r4_cse_unsw == ["flow_duration_ms", "flow_packets_per_s", "flow_bytes_per_s", "packet_length_mean"]
