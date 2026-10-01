"""Dataset audit (build spec section 6; Task 5).

Produces complete, machine-readable findings per file with chunked streaming,
plus a dataset-level summary. The audit is evidence, so it records counts rather
than conclusions: e.g. it reports the unknown-label list, it does not decide that
the data is "clean".
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from xrlids.datasets.loading import load_manifest
from xrlids.features.definitions import SEMANTIC_FIELDS
from xrlids.features.registry import FeatureRegistry
from xrlids.labels.contract import LabelContract, apply_label_contract
from xrlids.utils.columns import canonicalize_column, canonicalize_columns
from xrlids.utils.env import git_commit
from xrlids.utils.hashing import sha256_file
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
    """Audit a single dataframe in memory.

    Suitable for small in-memory test frames. For multi-GB files on disk,
    use :func:`audit_file` which streams in memory-bounded chunks.
    """
    n_rows, n_cols = frame.shape
    numeric = frame.select_dtypes(include=[np.number])

    nan_counts = {c: int(frame[c].isna().sum()) for c in frame.columns}
    inf_counts = {
        c: int(np.isinf(numeric[c].to_numpy(dtype=float)).sum()) for c in numeric.columns
    }

    duplicate_rows = int(frame.duplicated().sum())

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
        except Exception as exc:
            label_audit = {"error": f"{type(exc).__name__}: {exc}"}

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
    chunk_size: int = 100_000,
) -> dict[str, Any]:
    """Audit a CSV file per-file using chunked streaming for complete memory safety (Task 5).

    Produces complete per-file evidence without exceeding memory budget on large files.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"dataset file not found: {path}")

    size_bytes = path.stat().st_size
    file_sha256 = sha256_file(path)

    # Relative path provenance
    try:
        rel_path = str(path.relative_to(Path.cwd()))
    except ValueError:
        rel_path = str(path)

    # Provenance from manifest if available
    provenance_class = "unregistered"
    try:
        manifest = load_manifest()
        for d in manifest.get("datasets", []):
            if d.get("key") == dataset:
                for f in d.get("files", []):
                    if f.get("filename") == path.name or Path(f.get("path", "")).name == path.name:
                        provenance_class = f.get("provenance_class") or d.get("provenance_class", "unknown")
                        break
    except Exception:
        pass

    # Accumulators for streaming pass
    total_rows = 0
    duplicate_rows = 0
    seen_hashes: set[int] = set()

    original_headers: list[str] = []
    canonical_headers: list[str] = []
    label_col: str | None = None
    label_candidates = ["Label", "label", "attack_cat"]

    duration_candidates = ["Flow Duration", "dur", "flow_duration"]
    duration_col: str | None = None
    dur_negative = 0
    dur_zero = 0
    dur_nan = 0
    dur_min = float("inf")
    dur_max = float("-inf")

    nan_counts: dict[str, int] = {}
    inf_counts: dict[str, int] = {}
    repeated_headers_count = 0
    invalid_numeric_count = 0
    distinct_samples: dict[str, set[str]] = {}
    raw_label_counts: Counter[str] = Counter()

    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk_len = len(chunk)
        total_rows += chunk_len

        if not original_headers:
            original_headers = list(chunk.columns)
            canonical_headers = canonicalize_columns(original_headers)
            for c in original_headers:
                nan_counts[c] = 0
                inf_counts[c] = 0
                distinct_samples[c] = set()
                c_canon = canonicalize_column(c)
                if label_col is None and (c in label_candidates or c_canon.lower() in ["label", "attack_cat"]):
                    label_col = c
                if duration_col is None and (c in duration_candidates or c_canon.lower() in ["flow duration", "flow_duration", "dur"]):
                    duration_col = c

        # 1. Exact duplicate rows using uint64 row hashes
        hashes = pd.util.hash_pandas_object(chunk, index=False).to_numpy(dtype=np.uint64)
        for h in hashes:
            h_int = int(h)
            if h_int in seen_hashes:
                duplicate_rows += 1
            else:
                seen_hashes.add(h_int)

        # 2. Repeated headers
        if label_col and label_col in chunk.columns:
            rep_mask = chunk[label_col].astype(str).str.strip().str.lower() == label_col.lower()
            repeated_headers_count += int(rep_mask.sum())

        # 3. NaNs and Infs
        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        for c in chunk.columns:
            nan_counts[c] += int(chunk[c].isna().sum())
            # Track values for constant column detection
            if len(distinct_samples[c]) < 2:
                uniques = chunk[c].dropna().unique()
                for u in uniques:
                    distinct_samples[c].add(str(u))
                    if len(distinct_samples[c]) >= 2:
                        break

        for c in numeric_cols:
            inf_counts[c] += int(np.isinf(chunk[c].to_numpy(dtype=float)).sum())

        # 4. Duration anomalies
        if duration_col and duration_col in chunk.columns:
            d = pd.to_numeric(chunk[duration_col], errors="coerce")
            dur_negative += int((d < 0).sum())
            dur_zero += int((d == 0).sum())
            dur_nan += int(d.isna().sum())
            if d.notna().any():
                dur_min = min(dur_min, float(d.min()))
                dur_max = max(dur_max, float(d.max()))

        # 5. Label frequencies
        if label_col and label_col in chunk.columns:
            for lbl, cnt in chunk[label_col].dropna().astype(str).value_counts().items():
                raw_label_counts[lbl] += int(cnt)

    # Post-process constant columns
    constant_columns = [c for c, vals in distinct_samples.items() if len(vals) <= 1 and total_rows > 0]

    # Evaluate label contract
    accepted_labels: dict[str, int] = {}
    rejected_labels: dict[str, int] = {}
    unknown_label_rejections: list[dict[str, Any]] = []

    if contract is not None and dataset in contract.datasets:
        from xrlids.labels.contract import UnknownLabelError
        for raw_lbl, cnt in raw_label_counts.items():
            norm_lbl = contract.normalize(raw_lbl)
            try:
                family, binary = contract.classify(norm_lbl, dataset)
                accepted_labels[raw_lbl] = cnt
            except UnknownLabelError:
                rejected_labels[raw_lbl] = cnt
                unknown_label_rejections.append({
                    "raw_label": raw_lbl,
                    "normalized": norm_lbl,
                    "count": cnt,
                    "reason": "NOT_IN_BENIGN_OR_ATTACK_ALLOWLIST",
                })

    rows_accepted = sum(accepted_labels.values())
    rows_rejected = sum(rejected_labels.values())

    label_audit = {
        "label_column": label_col,
        "rows_total": total_rows,
        "rows_accepted": rows_accepted,
        "rows_rejected_unknown_label": rows_rejected,
        "distinct_labels": dict(raw_label_counts.most_common(50)),
    }

    # Feature extraction compatibility
    feature_avail: dict[str, bool] = {}
    feature_extraction_status = "unsupported"
    if registry is not None:
        cmap = registry.column_maps.get(dataset, {})
        canon_set = set(canonical_headers)
        # Check required fields
        resolved_semantics = []
        for sem, spec in cmap.items():
            if "column" in spec:
                if canonicalize_column(spec["column"]) in canon_set:
                    resolved_semantics.append(sem)
            elif "sum" in spec and "divide_by_sum" in spec:
                num = [canonicalize_column(x) for x in spec["sum"]]
                den = [canonicalize_column(x) for x in spec["divide_by_sum"]]
                if set(num + den) <= canon_set:
                    resolved_semantics.append(sem)
        for r in ["R10", "R15", "R20"]:
            try:
                r_feats = registry.rung_features(r)
                # Check if all required semantics for r_feats are resolved
                feature_avail[r] = len(resolved_semantics) >= len(cmap)
            except Exception:
                feature_avail[r] = False
        feature_extraction_status = "compatible" if feature_avail.get("R10") else "partial"

    duration_findings: dict[str, Any] = {}
    if duration_col:
        duration_findings[duration_col] = {
            "negative": dur_negative,
            "zero": dur_zero,
            "nan": dur_nan,
            "min": dur_min if dur_min != float("inf") else None,
            "max": dur_max if dur_max != float("-inf") else None,
        }

    return {
        "dataset": dataset,
        "filename": path.name,
        "relative_path": rel_path,
        "source_file": str(path),
        "size_bytes": size_bytes,
        "sha256": file_sha256,
        "rows": total_rows,
        "row_count": total_rows,
        "columns": len(original_headers),
        "column_count": len(original_headers),
        "column_names": original_headers,
        "original_headers": original_headers,
        "canonical_headers": canonical_headers,
        "label_column": label_col,
        "distinct_raw_labels": dict(raw_label_counts),
        "accepted_labels": accepted_labels,
        "rejected_labels": rejected_labels,
        "repeated_header_rows": repeated_headers_count,
        "nan_counts": {k: v for k, v in nan_counts.items() if v > 0},
        "inf_counts": {k: v for k, v in inf_counts.items() if v > 0},
        "total_nan": int(sum(nan_counts.values())),
        "total_inf": int(sum(inf_counts.values())),
        "duplicate_rows": duplicate_rows,
        "exact_duplicate_rows": duplicate_rows,
        "duplicate_row_fraction": float(duplicate_rows / total_rows) if total_rows else 0.0,
        "constant_columns": constant_columns,
        "duration_findings": duration_findings,
        "duration_anomalies": {"negative": dur_negative, "zero": dur_zero},
        "invalid_numeric_rows": invalid_numeric_count,
        "feature_availability": feature_avail,
        "feature_extraction_status": feature_extraction_status,
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit() or "uncommitted",
        "provenance_class": provenance_class,
        "source_provenance_classification": provenance_class,
        "label_audit": label_audit,
        "unknown_label_rejections": unknown_label_rejections,
        "mode": "streamed",
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
        "total_nan": int(sum(a.get("total_nan", 0) for a in audits)),
        "total_inf": int(sum(a.get("total_inf", 0) for a in audits)),
        "schema_variation": schema_variation,
    }
