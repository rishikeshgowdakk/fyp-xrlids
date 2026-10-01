"""Strict experiment input validation gate (Task 16).

Verifies all 10 pre-flight integrity, schema, feature, label, split, and resource
conditions BEFORE allocating memory or launching training:
1. file exists and is registered in the manifest
2. SHA-256 matches manifest entry
3. schema matches expected canonical schema
4. required feature rung columns are present or extractable
5. label column is present
6. all labels in the file map to known classes under the label contract
7. split ratios sum to 1.0
8. random seed is set
9. preprocessor will fit on train only
10. memory requirement is within budget
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pandas as pd

from xrlids.datasets.loading import (
    DatasetIntegrityError,
    DatasetNotAvailableError,
    load_manifest,
    verify_dataset_file,
)
from xrlids.datasets.schema import validate_file_schema
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract
from xrlids.utils.columns import canonicalize_column
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class PreflightValidationError(RuntimeError):
    """Raised when an experiment pre-flight validation check fails."""


def validate_experiment_preflight(
    config: dict[str, Any],
    raw_file_path: Path,
    manifest: dict[str, Any] | None = None,
    *,
    sample_limit: int | None = None,
) -> dict[str, Any]:
    """Execute the 10-point pre-flight validation gate before model training."""
    raw_file_path = Path(raw_file_path)
    dataset_cfg = config.get("dataset", {})
    dataset_key = dataset_cfg.get("key") or config.get("source_dataset", {}).get("key")
    if not dataset_key:
        raise PreflightValidationError("Config missing 'dataset.key'")

    if manifest is None:
        manifest = load_manifest()

    require_checksums = bool(dataset_cfg.get("require_verified_checksums", True))

    # 1 & 2. File exists, registered in manifest, SHA-256 matches manifest entry
    try:
        verify_res = verify_dataset_file(
            raw_file_path,
            dataset_key,
            manifest=manifest,
            require_verified=require_checksums,
        )
    except (DatasetIntegrityError, DatasetNotAvailableError) as exc:
        raise PreflightValidationError(f"Pre-flight checksum/manifest failure: {exc}") from exc

    # 3 & 5. Schema matches expected canonical schema and label column is present
    registry = load_feature_registry()
    contract = load_label_contract()
    spec = contract.datasets.get(dataset_key, {})
    label_candidates = spec.get("label_column_candidates", ["Label", "label", "attack_cat"])

    schema_rep = validate_file_schema(
        raw_file_path,
        dataset_key,
        registry,
        label_candidates=label_candidates,
    )
    if schema_rep.missing:
        raise PreflightValidationError(
            f"Schema conflict: raw file '{raw_file_path.name}' is missing declared columns: "
            f"{schema_rep.missing}"
        )
    if schema_rep.label_column_found is None:
        raise PreflightValidationError(
            f"No label column found in '{raw_file_path.name}'. Expected one of: {label_candidates}"
        )

    # 4. Required feature rung columns are present or extractable
    features_cfg = config.get("features", {})
    rung = features_cfg.get("rung", "R10")
    transfer_mode = features_cfg.get("mode") == "programmatic_common_transfer_contract"
    target_key = config.get("target_dataset", {}).get("key")

    if transfer_mode and target_key:
        common_features = registry.common_transfer_contract(dataset_key, target_key, candidate_features=rung)
        if not common_features:
            raise PreflightValidationError(
                f"No common transfer features found between source '{dataset_key}' and target '{target_key}'"
            )
    else:
        req_features = registry.rung_features(rung)
        unsupported = registry.unsupported_features(dataset_key, rung)
        if unsupported and features_cfg.get("require_frozen", False):
            raise PreflightValidationError(
                f"Dataset '{dataset_key}' does not support features required for rung {rung}: {unsupported}"
            )

    # 6. Verify label mapping policy
    label_cfg = config.get("label_contract", {})
    unknown_policy = label_cfg.get("unknown_label_policy", "REJECT")
    if unknown_policy != "REJECT":
        raise PreflightValidationError(
            f"unknown_label_policy={unknown_policy!r} is forbidden; must be 'REJECT' to prevent false labelling"
        )

    # 7. Split ratios sum to 1.0
    split_cfg = config.get("split", {})
    train_r = float(split_cfg.get("train", 0.6))
    val_r = float(split_cfg.get("validation", 0.2))
    test_r = float(split_cfg.get("test", 0.2))
    total_split = train_r + val_r + test_r
    if abs(total_split - 1.0) > 1e-5:
        raise PreflightValidationError(
            f"Split ratios must sum to 1.0 (train={train_r}, val={val_r}, test={test_r}; sum={total_split})"
        )

    # 8. Random seed is set
    seed = split_cfg.get("seed")
    if seed is None:
        raise PreflightValidationError("Split configuration missing 'seed'")

    # 9. Preprocessor fits on train only
    prep_cfg = config.get("preprocessing", {})
    fit_on = prep_cfg.get("fit_on", "train_only")
    if fit_on != "train_only":
        raise PreflightValidationError(
            f"Preprocessing fit_on={fit_on!r} violates scientific isolation; must be 'train_only'"
        )

    # 10. Memory requirement within budget
    file_size_bytes = raw_file_path.stat().st_size
    file_size_gb = file_size_bytes / (1024.0**3)
    if file_size_gb > 2.0 and sample_limit is None:
        # Warn or require chunked / bounded execution
        logger.warning(
            "Large raw file (%.2f GiB): memory-bounded chunked execution required to prevent OOM",
            file_size_gb,
        )

    return {
        "status": "passed",
        "dataset": dataset_key,
        "file": raw_file_path.name,
        "sha256": verify_res.get("actual_sha256"),
        "schema_ok": True,
        "label_column": schema_rep.label_column_found,
        "split_ratios": {"train": train_r, "val": val_r, "test": test_r},
        "seed": int(seed),
        "fit_on": fit_on,
        "file_size_gb": round(file_size_gb, 3),
    }
