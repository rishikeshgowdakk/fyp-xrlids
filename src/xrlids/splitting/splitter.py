"""Split construction (build spec section 20; scientific RULES 4 and 5).

TRAIN learns parameters, VALIDATION selects hyperparameters/thresholds, TEST is touched
once at final evaluation. The split is deterministic given a seed and is fully described
by a manifest (counts, class distribution, hashes, config, seed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from xrlids.splitting.leakage import audit_split_leakage
from xrlids.utils.hashing import dict_hash
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class SplitConfigurationError(ValueError):
    """Raised when a split cannot be produced as configured."""


@dataclass
class SplitConfig:
    """Declarative split configuration (from ``configs/splits/splits.yaml``)."""

    train: float = 0.6
    validation: float = 0.2
    test: float = 0.2
    seed: int = 42
    stratify: bool = True
    group_column: str | None = None
    group_by_attack_instance: bool = False
    time_column: str | None = None
    methodology: str = "stratified_random"
    rationale: str = ""

    def __post_init__(self) -> None:
        total = self.train + self.validation + self.test
        if abs(total - 1.0) > 1e-9:
            raise SplitConfigurationError(f"split ratios must sum to 1.0, got {total}")


@dataclass
class SplitResult:
    splits: dict[str, pd.DataFrame]
    assignment: pd.Series
    manifest: dict[str, Any] = field(default_factory=dict)
    leakage: dict[str, Any] = field(default_factory=dict)


def build_splits(
    frame: pd.DataFrame,
    labels: pd.Series,
    feature_columns: Sequence[str],
    config: SplitConfig,
    *,
    dataset: str,
    run_leakage_audit: bool = True,
) -> SplitResult:
    """Produce train/validation/test splits with an optional leakage audit.

    With ``group_column`` set, whole groups (e.g. an attack instance or a source host)
    stay inside one split, which prevents the classic near-duplicate leakage of the same
    flow appearing in both train and test.
    """
    if len(frame) != len(labels):
        raise SplitConfigurationError("frame and labels have different lengths")
    labels = labels.reset_index(drop=True)
    frame = frame.reset_index(drop=True)

    if config.group_column:
        if config.group_column not in frame.columns:
            raise SplitConfigurationError(
                f"group_column '{config.group_column}' is not present in the frame"
            )
        groups = frame[config.group_column].astype(str)
        outer = GroupShuffleSplit(n_splits=1, test_size=(config.validation + config.test), random_state=config.seed)
        train_idx, temp_idx = next(outer.split(frame, labels, groups=groups))
        # split the held-out portion into validation/test by group as well
        temp_groups = groups.iloc[temp_idx]
        inner = GroupShuffleSplit(
            n_splits=1,
            test_size=config.test / (config.validation + config.test),
            random_state=config.seed,
        )
        rel_val, rel_test = next(inner.split(temp_idx, groups=temp_groups))
        val_idx = temp_idx[rel_val]
        test_idx = temp_idx[rel_test]
    else:
        stratify = labels if config.stratify else None
        train_idx, temp_idx = train_test_split(
            np.arange(len(frame)),
            test_size=(config.validation + config.test),
            random_state=config.seed,
            stratify=stratify,
        )
        stratify_temp = labels.iloc[temp_idx] if config.stratify else None
        val_idx, test_idx = train_test_split(
            temp_idx,
            test_size=config.test / (config.validation + config.test),
            random_state=config.seed,
            stratify=stratify_temp,
        )

    assignment = pd.Series("unassigned", index=frame.index, name="split")
    assignment.iloc[np.asarray(train_idx)] = "train"
    assignment.iloc[np.asarray(val_idx)] = "validation"
    assignment.iloc[np.asarray(test_idx)] = "test"

    splits = {
        "train": frame.loc[assignment == "train"].reset_index(drop=True),
        "validation": frame.loc[assignment == "validation"].reset_index(drop=True),
        "test": frame.loc[assignment == "test"].reset_index(drop=True),
    }
    label_splits = {
        "train": labels.loc[assignment == "train"].reset_index(drop=True),
        "validation": labels.loc[assignment == "validation"].reset_index(drop=True),
        "test": labels.loc[assignment == "test"].reset_index(drop=True),
    }

    manifest = {
        "dataset": dataset,
        "methodology": config.methodology,
        "rationale": config.rationale,
        "ratios": {"train": config.train, "validation": config.validation, "test": config.test},
        "seed": config.seed,
        "stratified": config.stratify,
        "group_column": config.group_column,
        "time_column": config.time_column,
        "counts": {k: int(len(v)) for k, v in splits.items()},
        "class_distribution": {
            k: {
                "benign": int((v == 0).sum()),
                "attack": int((v == 1).sum()),
                "attack_fraction": float((v == 1).mean()) if len(v) else None,
            }
            for k, v in label_splits.items()
        },
        "split_config_hash": dict_hash(
            {
                "methodology": config.methodology,
                "ratios": [config.train, config.validation, config.test],
                "seed": config.seed,
                "stratified": config.stratify,
                "group_column": config.group_column,
            }
        ),
    }

    leakage: dict[str, Any] = {}
    if run_leakage_audit:
        leakage = audit_split_leakage(
            splits,
            feature_columns,
            group_column=config.group_column,
            time_column=config.time_column,
        )
        if leakage["status"] == "fail":
            logger.error("leakage audit FAILED for %s: %s", dataset, leakage["failed_checks"])
        else:
            logger.info("leakage audit passed for %s", dataset)

    return SplitResult(splits=splits, assignment=assignment, manifest=manifest, leakage=leakage)
