"""Split construction (build spec section 20; scientific RULES 4 and 5).

TRAIN learns parameters, VALIDATION selects hyperparameters/thresholds, TEST is touched
once at final evaluation. The split is deterministic given a seed and is fully described
by a manifest (counts, class distribution, hashes, config, seed).

Two split families are supported:

* ``stratified_random`` (default) and optional random group splits.
* ``temporal``: rows are sorted by a real timestamp and cut into contiguous
  train/validation/test blocks. Cut points are moved forward to the next hour
  boundary where possible so flows sharing a timestamp are not split across
  populations.
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
    time_fallback_group_column: str | None = "source_file"
    methodology: str = "stratified_random"
    rationale: str = ""
    duplicate_policy: str = "deduplicate_features"  # "deduplicate_features" | "retain_with_subset_evaluation" | "none"

    def __post_init__(self) -> None:
        total = self.train + self.validation + self.test
        if abs(total - 1.0) > 1e-9:
            raise SplitConfigurationError(f"split ratios must sum to 1.0, got {total}")
        valid_policies = {"deduplicate_features", "retain_with_subset_evaluation", "none"}
        if self.duplicate_policy not in valid_policies:
            raise SplitConfigurationError(
                f"invalid duplicate_policy '{self.duplicate_policy}'; expected one of {sorted(valid_policies)}"
            )


@dataclass
class SplitResult:
    splits: dict[str, pd.DataFrame]
    assignment: pd.Series
    manifest: dict[str, Any] = field(default_factory=dict)
    leakage: dict[str, Any] = field(default_factory=dict)
    test_duplicate_mask: pd.Series | None = None
    label_splits: dict[str, pd.Series] = field(default_factory=dict)
    provenance_splits: dict[str, pd.DataFrame] = field(default_factory=dict)


def _parse_time_series(raw: pd.Series) -> pd.Series:
    """Parse a timestamp column without guessing silently.

    CSE-CIC-IDS2018 uses ``DD/MM/YYYY HH:MM:SS``. Other datasets may use ISO
    timestamps; both are attempted. Values that cannot be parsed are returned as
    ``NaT`` and handled (or rejected) by the caller.
    """
    if pd.api.types.is_datetime64_any_dtype(raw):
        parsed = raw.copy()
    elif pd.api.types.is_numeric_dtype(raw):
        parsed = pd.to_datetime(raw, unit="s", errors="coerce")
    else:
        parsed = pd.to_datetime(raw, format="%d/%m/%Y %H:%M:%S", errors="coerce")
        if parsed.isna().mean() > 0.5:
            parsed = pd.to_datetime(raw, errors="coerce", dayfirst=True)

    if isinstance(parsed.dtype, pd.DatetimeTZDtype):
        parsed = parsed.dt.tz_localize(None)
    return parsed


def _resolve_time_series(
    frame: pd.DataFrame,
    provenance: pd.DataFrame | None,
    config: SplitConfig,
) -> tuple[pd.Series, int]:
    """Return an effective timestamp per row plus the count of repaired values.

    Invalid timestamps are repaired from the maximum valid timestamp of the same
    capture group (by default ``source_file``). This matters for CSE-CIC-IDS2018,
    where a handful of rows carry an epoch-zero sentinel while the rest of the file
    has a real capture timestamp. Rows that still cannot be assigned a time raise a
    configuration error rather than silently entering the wrong split.
    """
    assert config.time_column is not None
    if config.time_column in frame.columns:
        raw = frame[config.time_column]
    elif provenance is not None and config.time_column in provenance.columns:
        raw = provenance[config.time_column]
    else:
        raise SplitConfigurationError(
            f"time_column '{config.time_column}' is not present in the frame or provenance"
        )

    times = _parse_time_series(raw).reset_index(drop=True)
    fallback_count = 0
    # Epoch-zero sentinels are not meaningful capture times. Treat anything before
    # 2000 as malformed for this project's datasets.
    malformed = times.isna() | (times < pd.Timestamp("2000-01-01"))
    if malformed.any():
        fallback_col = config.time_fallback_group_column
        if (
            fallback_col
            and provenance is not None
            and fallback_col in provenance.columns
            and len(provenance) == len(times)
        ):
            groups = provenance[fallback_col].reset_index(drop=True).astype(str)
            group_max = times.where(~malformed).groupby(groups).transform("max")
            times = times.where(~malformed, group_max)
            fallback_count = int(malformed.sum())
            logger.warning(
                "temporal split: repaired %d malformed timestamp(s) from %s group maxima",
                fallback_count,
                fallback_col,
            )

    if times.isna().any():
        raise SplitConfigurationError(
            f"time_column '{config.time_column}' has {int(times.isna().sum())} missing/"
            "unparseable timestamps and no usable fallback group column"
        )
    return times, fallback_count


def _nearest_hour_cut(
    sorted_times: pd.Series,
    target: int,
    *,
    min_cut: int = 1,
    max_cut: int | None = None,
) -> int:
    """Move a target row index to the nearest hour boundary inside the allowed range.

    Choosing the nearest boundary (rather than always moving forward) keeps the
    observed split proportions close to the requested 60/20/20. The boundary is
    implemented with ``searchsorted(..., side='left')`` so all flows sharing the
    same hour stay together and no flow is split across populations.
    """
    n = len(sorted_times)
    max_cut = n - 1 if max_cut is None else min(max_cut, n - 1)
    target = max(0, min(n, int(target)))
    if target <= min_cut or target >= max_cut:
        return int(max(min(target, max_cut), min_cut))

    t = sorted_times.iloc[target]
    if pd.isna(t):
        return int(target)

    candidates = {t.floor("h"), t.ceil("h")}
    if t == t.floor("h"):
        candidates.add(t - pd.Timedelta(hours=1))
        candidates.add(t + pd.Timedelta(hours=1))

    times_np = sorted_times.to_numpy()
    best: int | None = None
    for boundary in candidates:
        idx = int(np.searchsorted(times_np, np.datetime64(boundary), side="left"))
        if idx <= min_cut or idx >= max_cut:
            continue
        if best is None:
            best = idx
            continue
        # Closest to the requested quantile; on a tie prefer the later cut.
        if abs(idx - target) < abs(best - target) or (
            abs(idx - target) == abs(best - target) and idx > best
        ):
            best = idx

    return int(best if best is not None else target)


def _temporal_indices(
    times: pd.Series,
    config: SplitConfig,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    """Return contiguous temporal train/validation/test indices."""
    n = len(times)
    if n < 3:
        raise SplitConfigurationError("temporal split requires at least three rows")

    order = np.argsort(times.to_numpy(), kind="stable")
    sorted_times = times.iloc[order].reset_index(drop=True)
    target_train = int(round(n * config.train))
    target_val = int(round(n * (config.train + config.validation)))

    cut_train = _nearest_hour_cut(sorted_times, target_train, min_cut=1, max_cut=n - 2)
    cut_val = _nearest_hour_cut(
        sorted_times, target_val, min_cut=cut_train + 1, max_cut=n - 1
    )
    strategy = "nearest_hour_boundary"
    if not (0 < cut_train < cut_val < n):
        # Very short or highly clustered time spans may not permit an hour-aligned
        # cut. Fall back to exact quantile positions and record why.
        cut_train, cut_val = target_train, target_val
        strategy = "exact_index_fallback"

    if not (0 < cut_train < cut_val < n):
        raise SplitConfigurationError(
            "temporal split produced an empty split; adjust ratios or time span"
        )

    train_idx = order[:cut_train]
    val_idx = order[cut_train:cut_val]
    test_idx = order[cut_val:]

    ranges: dict[str, dict[str, Any]] = {}
    for name, idx in (("train", train_idx), ("validation", val_idx), ("test", test_idx)):
        selected = times.iloc[idx]
        ranges[name] = {
            "min": str(selected.min()),
            "max": str(selected.max()),
            "rows": int(len(idx)),
        }

    info = {
        "strategy": strategy,
        "target_cuts": {"train_end": target_train, "validation_end": target_val},
        "actual_cuts": {"train_end": int(cut_train), "validation_end": int(cut_val)},
        "ranges": ranges,
        "hour_aligned": strategy == "nearest_hour_boundary",
    }
    return train_idx, val_idx, test_idx, info


def build_splits(
    frame: pd.DataFrame,
    labels: pd.Series,
    feature_columns: Sequence[str],
    config: SplitConfig,
    *,
    dataset: str,
    provenance: pd.DataFrame | None = None,
    run_leakage_audit: bool = True,
) -> SplitResult:
    """Produce train/validation/test splits with an optional leakage audit.

    With ``group_column`` set, whole groups (e.g. an attack instance or a source host)
    stay inside one split, which prevents the classic near-duplicate leakage of the same
    flow appearing in both train and test.

    With ``time_column`` set, rows are ordered by that timestamp and cut into contiguous
    train/validation/test blocks. The test block is strictly later than validation, and
    validation is strictly later than train. Class stratification is intentionally not
    applied; the resulting class distribution is reported and is part of the evidence.
    """
    if len(frame) != len(labels):
        raise SplitConfigurationError("frame and labels have different lengths")
    labels = labels.reset_index(drop=True)
    frame = frame.reset_index(drop=True)
    if provenance is not None and len(provenance) != len(frame):
        raise SplitConfigurationError(
            "provenance must align row-for-row with frame; "
            f"got {len(provenance)} provenance rows for {len(frame)} feature rows"
        )

    duplicate_accounting: dict[str, Any] = {
        "policy": config.duplicate_policy,
        "input_rows": int(len(frame)),
    }
    test_duplicate_mask: pd.Series | None = None

    if config.duplicate_policy == "deduplicate_features":
        # Policy A: Feature-level deduplication before splitting (eliminates L-01/L-02 leakage)
        feat_subset = [c for c in feature_columns if c in frame.columns]
        is_dupe = frame.duplicated(subset=feat_subset, keep="first")
        n_dupes = int(is_dupe.sum())
        duplicate_accounting["duplicate_rows_dropped"] = n_dupes
        duplicate_accounting["unique_rows_retained"] = int(len(frame) - n_dupes)
        duplicate_accounting["duplicate_fraction"] = float(n_dupes / max(1, len(frame)))
        if n_dupes > 0:
            logger.info(
                "Policy A: deduplicating %d duplicate feature rows (%0.2f%%)",
                n_dupes,
                duplicate_accounting["duplicate_fraction"] * 100,
            )
            frame = frame.loc[~is_dupe].reset_index(drop=True)
            labels = labels.loc[~is_dupe].reset_index(drop=True)
            if provenance is not None:
                provenance = provenance.loc[~is_dupe].reset_index(drop=True)

    elif config.duplicate_policy == "retain_with_subset_evaluation":
        # Policy B: Retain duplicates; tag rows to allow separate duplicate / unique evaluation
        feat_subset = [c for c in feature_columns if c in frame.columns]
        is_dupe_vector = frame.duplicated(subset=feat_subset, keep=False)
        n_dupe_rows = int(is_dupe_vector.sum())
        duplicate_accounting["duplicate_rows_total"] = n_dupe_rows
        duplicate_accounting["unique_vectors"] = int(len(frame.drop_duplicates(subset=feat_subset)))
        duplicate_accounting["duplicate_fraction"] = float(n_dupe_rows / max(1, len(frame)))
    else:
        duplicate_accounting["note"] = "no duplicate handling applied"

    temporal_info: dict[str, Any] | None = None
    if config.time_column:
        times, fallback_count = _resolve_time_series(frame, provenance, config)
        train_idx, val_idx, test_idx, temporal_info = _temporal_indices(times, config)
        temporal_info["fallback_count"] = fallback_count
        temporal_info["fallback_group_column"] = config.time_fallback_group_column
    elif config.group_column:
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

    if config.duplicate_policy == "retain_with_subset_evaluation":
        test_duplicate_mask = is_dupe_vector.iloc[test_idx].reset_index(drop=True)
        duplicate_accounting["test_duplicate_rows"] = int(test_duplicate_mask.sum())
        duplicate_accounting["test_unique_rows"] = int((~test_duplicate_mask).sum())

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

    provenance_splits: dict[str, pd.DataFrame] = {}
    if provenance is not None:
        prov_copy = provenance.copy().reset_index(drop=True)
        prov_copy["split_membership"] = assignment.to_numpy()
        provenance_splits = {
            "train": prov_copy.loc[assignment == "train"].reset_index(drop=True),
            "validation": prov_copy.loc[assignment == "validation"].reset_index(drop=True),
            "test": prov_copy.loc[assignment == "test"].reset_index(drop=True),
        }

    methodology = config.methodology
    if config.time_column and methodology == "stratified_random":
        methodology = "temporal"
    if config.time_column and methodology not in ("temporal", "grouped_temporal"):
        methodology = "temporal"

    checks_performed = [
        "feature_deduplication_audit",
        "train_val_test_disjointness",
        "class_distribution_audit",
        "exact_duplicate_leakage_audit",
    ]
    checks_not_performed: list[str] = []
    if config.time_column:
        checks_performed.extend(["temporal_ordering_audit", "temporal_disjointness"])
    else:
        checks_not_performed.append(
            "strict_timestamp_monotonic_ordering (timestamps absent or non-monotonic in source data)"
        )
    if config.group_column:
        checks_performed.append("group_disjointness")
    else:
        checks_not_performed.append("group_overlap (no group column supplied)")

    manifest = {
        "dataset": dataset,
        "methodology": methodology,
        "rationale": config.rationale,
        "duplicate_policy": config.duplicate_policy,
        "duplicate_accounting": duplicate_accounting,
        "ordering_basis": "timestamp_sorted" if config.time_column else "arrival_order",
        "checks_performed": checks_performed,
        "checks_not_performed": checks_not_performed,
        "ratios": {"train": config.train, "validation": config.validation, "test": config.test},
        "observed_ratios": {
            k: float(len(v) / max(1, len(frame))) for k, v in splits.items()
        },
        "seed": config.seed,
        "stratified": bool(config.stratify and not config.time_column),
        "group_column": config.group_column,
        "time_column": config.time_column,
        "temporal": temporal_info,
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
                "methodology": methodology,
                "ratios": [config.train, config.validation, config.test],
                "seed": config.seed,
                "stratified": config.stratify,
                "group_column": config.group_column,
                "time_column": config.time_column,
                "time_fallback_group_column": config.time_fallback_group_column,
                "duplicate_policy": config.duplicate_policy,
            }
        ),
    }

    leakage: dict[str, Any] = {}
    if run_leakage_audit:
        # The leakage audit needs metadata columns to perform L-03/L-05. Keep them
        # out of the model feature matrix by attaching them only to audit copies.
        audit_splits: dict[str, pd.DataFrame] = {}
        for name, split_frame in splits.items():
            audit_frame = split_frame.copy()
            meta = provenance_splits.get(name)
            if meta is not None and len(meta) == len(audit_frame):
                for column in (config.group_column, config.time_column):
                    if column and column in meta.columns and column not in audit_frame.columns:
                        audit_frame[column] = meta[column].to_numpy()
            audit_splits[name] = audit_frame
        leakage = audit_split_leakage(
            audit_splits,
            feature_columns,
            group_column=config.group_column,
            time_column=config.time_column,
        )
        if leakage["status"] == "fail":
            logger.error("leakage audit FAILED for %s: %s", dataset, leakage["failed_checks"])
        else:
            logger.info("leakage audit passed for %s", dataset)

    return SplitResult(
        splits=splits,
        assignment=assignment,
        manifest=manifest,
        leakage=leakage,
        test_duplicate_mask=test_duplicate_mask,
        label_splits=label_splits,
        provenance_splits=provenance_splits,
    )
