"""Unit tests for experiment preflight validation gate (Task 16)."""

from __future__ import annotations

import hashlib
from pathlib import Path
import pytest

from xrlids.experiments.preflight import PreflightValidationError, validate_experiment_preflight


@pytest.fixture
def mock_exp_setup(tmp_path: Path):
    columns = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Packet Length Mean", "Packet Length Std", "SYN Flag Count",
        "ACK Flag Count", "RST Flag Count", "FIN Flag Count",
        "Flow IAT Mean", "Flow IAT Std", "Fwd Packet Length Mean",
        "Bwd Packet Length Mean", "Active Mean", "Idle Mean",
        "Subflow Fwd Bytes", "Subflow Bwd Bytes", "Label"
    ]
    vals = [
        "1000", "1", "1", "10.0", "10.0", "10.0", "1.0", "1", "1", "0", "0",
        "1", "1", "10.0", "10.0", "1", "1", "5", "5", "BENIGN"
    ]
    raw_file = tmp_path / "mock_cicids2017.csv"
    raw_file.write_text(",".join(columns) + "\n" + ",".join(vals) + "\n")
    sha = hashlib.sha256(raw_file.read_bytes()).hexdigest()

    manifest = {
        "datasets": [
            {
                "key": "cicids2017",
                "files": [{"filename": raw_file.name, "path": str(raw_file), "sha256": sha}],
            }
        ]
    }

    config = {
        "dataset": {
            "key": "cicids2017",
            "file": raw_file.name,
            "require_verified_checksums": True,
        },
        "features": {"rung": "R10"},
        "label_contract": {"unknown_label_policy": "REJECT"},
        "split": {"train": 0.6, "validation": 0.2, "test": 0.2, "seed": 42},
        "preprocessing": {"fit_on": "train_only"},
    }

    return config, raw_file, manifest


def test_preflight_valid(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    res = validate_experiment_preflight(config, raw_file, manifest=manifest)
    assert res["status"] == "passed"
    assert res["seed"] == 42


def test_preflight_fails_invalid_split_sum(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    config["split"]["train"] = 0.5  # sum = 0.9 != 1.0
    with pytest.raises(PreflightValidationError, match="Split ratios must sum to 1.0"):
        validate_experiment_preflight(config, raw_file, manifest=manifest)


def test_preflight_fails_missing_seed(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    config["split"]["seed"] = None
    with pytest.raises(PreflightValidationError, match="missing 'seed'"):
        validate_experiment_preflight(config, raw_file, manifest=manifest)


def test_preflight_fails_non_train_only_fit(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    config["preprocessing"]["fit_on"] = "all_data"
    with pytest.raises(PreflightValidationError, match="must be 'train_only'"):
        validate_experiment_preflight(config, raw_file, manifest=manifest)


def test_preflight_fails_invalid_label_policy(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    config["label_contract"]["unknown_label_policy"] = "BENIGN"
    with pytest.raises(PreflightValidationError, match="must be 'REJECT'"):
        validate_experiment_preflight(config, raw_file, manifest=manifest)


def test_preflight_fails_checksum_mismatch(mock_exp_setup):
    config, raw_file, manifest = mock_exp_setup
    manifest["datasets"][0]["files"][0]["sha256"] = "badc0ffee"
    with pytest.raises(PreflightValidationError, match="Checksum mismatch"):
        validate_experiment_preflight(config, raw_file, manifest=manifest)
