"""Semantic extraction and canonical feature computation.

Two stages, deliberately separated:

1. ``extract_semantics`` maps a dataset's raw columns to dataset-independent semantic
   fields, honouring unit scales. Missing source columns are reported, never guessed.
2. ``compute_features`` applies the canonical formulae to those semantic fields.

A feature whose required semantic fields are absent is reported *unavailable*; it is not
silently approximated with a substitute column.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

from xrlids.features.definitions import FeatureComputationError, feature_spec
from xrlids.features.registry import FeatureRegistry


class FeatureValidationError(ValueError):
    """Raised when a computed feature matrix is not fit to model on."""


@dataclass
class FeatureMatrix:
    """A computed feature matrix plus the provenance needed to interpret it."""

    frame: pd.DataFrame
    available: list[str]
    unavailable: list[str]
    dataset: str
    schema_hash: str
    validation: dict[str, Any]


def _numeric(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame.columns:
        raise KeyError(column)
    return pd.to_numeric(frame[column], errors="coerce")


def extract_semantics(
    frame: pd.DataFrame,
    dataset: str,
    registry: FeatureRegistry,
    *,
    strict: bool = True,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Map raw columns to semantic fields for one dataset.

    Returns the semantic frame and a report describing which semantic fields were
    resolved, which were absent, and the raw columns each used.
    """
    if dataset not in registry.column_maps:
        raise KeyError(f"no column map declared for dataset '{dataset}'")

    mapping = registry.column_maps[dataset]
    resolved: dict[str, pd.Series] = {}
    provenance: dict[str, Any] = {}
    missing_columns: list[str] = []

    for semantic, spec in mapping.items():
        if "column" in spec:
            column = spec["column"]
            if column not in frame.columns:
                missing_columns.append(column)
                continue
            series = _numeric(frame, column)
            scale = float(spec.get("scale", 1.0))
            if scale != 1.0:
                series = series * scale
            resolved[semantic] = series
            provenance[semantic] = {"source_columns": [column], "scale": scale}
        elif "sum" in spec and "divide_by_sum" in spec:
            num_cols = list(spec["sum"])
            den_cols = list(spec["divide_by_sum"])
            absent = [c for c in (*num_cols, *den_cols) if c not in frame.columns]
            if absent:
                missing_columns.extend(absent)
                continue
            numerator = sum(_numeric(frame, c) for c in num_cols)
            denominator = sum(_numeric(frame, c) for c in den_cols)
            resolved[semantic] = numerator / denominator.replace(0, np.nan)
            provenance[semantic] = {
                "source_columns": [*num_cols, *den_cols],
                "derivation": f"sum({num_cols}) / sum({den_cols})",
            }
        else:
            raise ValueError(f"unrecognised column-map entry for semantic '{semantic}': {spec}")

    report = {
        "dataset": dataset,
        "semantic_resolved": sorted(resolved),
        "semantic_absent": sorted(set(mapping) - set(resolved)),
        "raw_columns_missing": sorted(set(missing_columns)),
        "provenance": provenance,
    }

    if strict and missing_columns:
        raise FeatureValidationError(
            f"dataset '{dataset}' is missing required raw columns: {sorted(set(missing_columns))}. "
            "Confirm column names with scripts/phase1/01_dataset_audit.py; do not guess."
        )

    return pd.DataFrame(resolved, index=frame.index), report


def _with_derived(semantics: pd.DataFrame) -> pd.DataFrame:
    """Add derived semantic fields that exist whenever their inputs do."""
    out = semantics.copy()
    if {"total_fwd_packets", "total_bwd_packets"} <= set(out.columns):
        # Preserve NaN semantics: if either side is unknown the total is unknown.
        out["total_packets"] = out["total_fwd_packets"] + out["total_bwd_packets"]
    if {"fwd_bytes", "bwd_bytes"} <= set(out.columns):
        out["total_bytes"] = out["fwd_bytes"] + out["bwd_bytes"]
    return out


def compute_features(
    semantics: pd.DataFrame,
    features: Sequence[str],
    *,
    dataset: str,
    strict: bool = True,
) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Compute canonical features from semantic fields.

    Returns ``(frame, available, unavailable)``. With ``strict=True`` a feature whose
    inputs are missing raises rather than returning a column of NaNs.
    """
    sem = _with_derived(semantics)
    sem_map: dict[str, pd.Series] = {c: sem[c] for c in sem.columns}

    available: list[str] = []
    unavailable: list[str] = []
    columns: dict[str, pd.Series] = {}

    for name in features:
        spec = feature_spec(name)
        try:
            columns[name] = spec.fn(sem_map)
            available.append(name)
        except FeatureComputationError as exc:
            if strict:
                raise FeatureValidationError(
                    f"feature '{name}' cannot be computed for dataset '{dataset}': {exc}"
                ) from exc
            columns[name] = pd.Series(np.nan, index=sem.index, name=name)
            unavailable.append(name)

    return pd.DataFrame(columns, index=sem.index), available, unavailable


def build_feature_matrix(
    raw_frame: pd.DataFrame,
    dataset: str,
    rung: str,
    registry: FeatureRegistry,
    *,
    strict: bool = True,
    validate: bool = True,
) -> FeatureMatrix:
    """End-to-end: raw rows -> semantic fields -> canonical feature matrix."""
    features = registry.rung_features(rung)
    semantics, extraction_report = extract_semantics(raw_frame, dataset, registry, strict=strict)
    frame, available, unavailable = compute_features(
        semantics, features, dataset=dataset, strict=strict
    )

    report: dict[str, Any] = {
        "extraction": extraction_report,
        "available": available,
        "unavailable": unavailable,
        "rung": rung,
    }
    if validate:
        report["validation"] = validate_feature_matrix(frame, features, strict=strict)

    return FeatureMatrix(
        frame=frame,
        available=available,
        unavailable=unavailable,
        dataset=dataset,
        schema_hash=registry.schema_hash(rung),
        validation=report,
    )


def validate_feature_matrix(
    frame: pd.DataFrame,
    features: Iterable[str],
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Check a feature matrix for non-finite values and constant columns.

    Non-finite values are *counted*, and with ``strict=True`` a matrix containing them is
    rejected: the cleaning policy must handle missing/infinite values explicitly rather
    than a model silently learning from NaN.
    """
    features = list(features)
    missing = [f for f in features if f not in frame.columns]
    if missing:
        raise FeatureValidationError(f"feature matrix is missing columns: {missing}")

    sub = frame[features]
    nan_counts = {f: int(sub[f].isna().sum()) for f in features}
    inf_counts = {
        f: int(np.isinf(sub[f].to_numpy(dtype=float, na_value=np.nan)).sum()) for f in features
    }
    constant = [f for f in features if sub[f].nunique(dropna=True) <= 1]

    report = {
        "n_rows": int(len(sub)),
        "nan_counts": nan_counts,
        "inf_counts": inf_counts,
        "constant_columns": constant,
        "total_nan": int(sum(nan_counts.values())),
        "total_inf": int(sum(inf_counts.values())),
    }

    if strict and (report["total_inf"] > 0):
        offending = {k: v for k, v in inf_counts.items() if v}
        raise FeatureValidationError(f"feature matrix contains infinite values: {offending}")

    return report
