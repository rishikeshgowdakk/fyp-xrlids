"""Dataset audit (build spec section 6).

Produces machine-readable findings per file, plus a dataset-level summary. The audit is
evidence, so it records counts rather than conclusions: e.g. it reports the unknown-label
list, it does not decide that the data is "clean".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from xrlids.features.registry import FeatureRegistry
from xrlids.labels.contract import LabelContract, apply_label_contract
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _dtype_summary(frame: pd.DataFrame) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dtype in frame.dtypes.astype(str):
        counts[dtype] = counts.get(dtype, 0) + 1
    return counts


def audit_frame(
    frame: pd.DataFrame,
    *,
    dataset: str,
    source_file: str,
    contract: LabelContract | None = None,
    registry: FeatureRegistry | None = None,
    near_constant_threshold: float = 0.999,
) -> dict[str, Any]:
    """Audit a single dataframe.

    Note: this reads the whole frame in memory. For multi-GB files, call the file-level
    auditor which streams in chunks.
    """
    n_rows, n_cols = frame.shape
    numeric = frame.select_dtypes(include=[np.number])

    nan_counts = {c: int(frame[c].isna().sum()) for c in frame.columns}
    inf_counts = {
        c: int(np.isinf(numeric[c].to_numpy(dtype=float)).sum()) for c in numeric.columns
    }

    duplicate_rows = int(frame.duplicated().sum())

    # constant / near-constant columns
    constant_cols, near_constant_cols = [], []
    for c in frame.columns:
        try:
            top = frame[c].value_counts(dropna=False, normalize=True)
        except TypeError:
            continue
        if len(top) == 0:
            continue
        if len(top) == 1:
            constant_cols.append(c)
        elif float(top.iloc[0]) >= near_constant_threshold:
            near_constant_cols.append(c)

    # identify identifier/label columns (must never be features)
    identifier_cols = [
        c for c in frame.columns if registry is not None and registry.is_excluded_column(c)
    ]

    label_audit: dict[str, Any] = {}
    rejections: list[dict[str, Any]] = []
    if contract is not None and dataset in contract.datasets:
        try:
            application = apply_label_contract(frame, dataset, contract)
            label_audit = application.stats
            label_audit["distinct_labels"] = (
                application.normalized.value_counts().head(50).to_dict()
            )
            if not application.rejections.empty:
                rejections = application.rejections.to_dict(orient="records")
        except Exception as exc:  # surfaced, not swallowed
            label_audit = {"error": f"{type(exc).__name__}: {exc}"}

    # duration sanity (dataset-specific candidate columns)
    duration_findings: dict[str, Any] = {}
    for candidate in ("Flow Duration", "dur"):
        if candidate in frame.columns:
            d = pd.to_numeric(frame[candidate], errors="coerce")
            duration_findings[candidate] = {
                "negative": int((d < 0).sum()),
                "zero": int((d == 0).sum()),
                "nan": int(d.isna().sum()),
                "min": float(d.min()) if d.notna().any() else None,
                "max": float(d.max()) if d.notna().any() else None,
            }

    return {
        "dataset": dataset,
        "source_file": source_file,
        "rows": int(n_rows),
        "columns": int(n_cols),
        "column_names": list(frame.columns),
        "dtypes": _dtype_summary(frame),
        "nan_counts": {k: v for k, v in nan_counts.items() if v},
        "inf_counts": {k: v for k, v in inf_counts.items() if v},
        "total_nan": int(sum(nan_counts.values())),
        "total_inf": int(sum(inf_counts.values())),
        "duplicate_rows": duplicate_rows,
        "duplicate_row_fraction": float(duplicate_rows / n_rows) if n_rows else 0.0,
        "constant_columns": constant_cols,
        "near_constant_columns": near_constant_cols,
        "identifier_or_label_columns": identifier_cols,
        "duration_findings": duration_findings,
        "label_audit": label_audit,
        "unknown_label_rejections": rejections,
    }


def audit_file(
    path: str | Path,
    *,
    dataset: str,
    contract: LabelContract | None = None,
    registry: FeatureRegistry | None = None,
    chunk_size: int | None = None,
) -> dict[str, Any]:
    """Audit a CSV file, optionally streaming for large inputs."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"dataset file not found: {path}")

    if chunk_size is None:
        frame = pd.read_csv(path, low_memory=False)
        result = audit_frame(frame, dataset=dataset, source_file=str(path), contract=contract, registry=registry)
        result["size_bytes"] = path.stat().st_size
        return result

    # streaming mode: accumulate counts without holding the whole file
    rows = 0
    duplicates = 0
    seen: set[Any] = set()
    columns: list[str] = []
    for chunk in pd.read_csv(path, low_memory=False, chunksize=chunk_size):
        if not columns:
            columns = list(chunk.columns)
        rows += len(chunk)
        for record in chunk.itertuples(index=False, name=None):
            if record in seen:
                duplicates += 1
            else:
                seen.add(record)
    return {
        "dataset": dataset,
        "source_file": str(path),
        "rows": rows,
        "columns": len(columns),
        "column_names": columns,
        "duplicate_rows": duplicates,
        "size_bytes": path.stat().st_size,
        "mode": "streamed",
        "note": "streamed audit reports rows/duplicates only; run without chunk_size for full schema detail",
    }


def summarize_audits(audits: list[dict[str, Any]]) -> dict[str, Any]:
    """Dataset-level summary across files, never assuming identical schemas."""
    schemas: dict[str, list[str]] = {}
    for a in audits:
        schemas.setdefault(a["dataset"], []).append(str(a["source_file"]))
    schema_variation: dict[str, Any] = {}
    for dataset in {a["dataset"] for a in audits}:
        per_file = {a["source_file"]: tuple(a.get("column_names", [])) for a in audits if a["dataset"] == dataset}
        distinct = {cols for cols in per_file.values()}
        schema_variation[dataset] = {
            "n_files": len(per_file),
            "distinct_column_sets": len(distinct),
            "schemas_identical": len(distinct) == 1,
            "files": {k: len(v) for k, v in per_file.items()},
        }
    return {
        "n_files_audited": len(audits),
        "datasets": sorted({a["dataset"] for a in audits}),
        "total_rows": int(sum(a["rows"] for a in audits)),
        "total_duplicate_rows": int(sum(a["duplicate_rows"] for a in audits)),
        "schema_variation": schema_variation,
    }
