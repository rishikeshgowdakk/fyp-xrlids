"""Multi-File Dataset Population Loader and Accounting Engine (Tasks 1, 2, 5, 6, 7).

Provides rigorous, memory-safe loading of multi-file dataset populations:
- Reconciles every input file against manifest and verifies SHA-256 checksums.
- Preserves fine-grained row provenance (dataset, source file, source row index, global order,
  raw label, canonical label, binary label, attack family, split membership).
- NEVER leaks provenance columns into predictive feature spaces.
- Mathematically validates multi-stage row accounting:
      raw_rows - sum(all_removed) == final_modeling_rows
- Analyzes and resolves duplicate-label conflicts (identical feature vectors with conflicting labels).
- Generates machine-readable `experiment_population.json` manifests.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.datasets.loading import DatasetIntegrityError, load_manifest, verify_dataset_file
from xrlids.features.compute import compute_features, extract_semantics
from xrlids.features.registry import FeatureRegistry
from xrlids.labels.contract import LabelContract
from xrlids.preprocessing.cleaning import clean_dataset_frame
from xrlids.utils.hashing import sha256_file
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class AccountingReconciliationError(ValueError):
    """Raised when row accounting fails mathematical reconciliation."""


class DuplicateConflictError(ValueError):
    """Raised when duplicate-label conflicts violate experimental constraints."""


@dataclass
class PopulationFileRecord:
    """Provenance and audit record for a single input CSV file."""

    filename: str
    relative_path: str
    sha256: str
    size_bytes: int
    raw_rows: int
    provenance_class: str
    status: str
    accounting: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DuplicateConflictReport:
    """Detailed audit of duplicate feature vectors with conflicting ground-truth labels."""

    total_unique_vectors_with_duplicates: int = 0
    total_conflicting_vectors: int = 0
    total_conflicting_rows: int = 0
    benign_attack_conflicts: int = 0
    family_conflicts: int = 0
    policy_applied: str = "reject_conflicts"
    rows_dropped: int = 0
    conflict_examples: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PopulationAccounting:
    """Mathematically reconciled multi-stage population accounting."""

    per_file: dict[str, dict[str, int]] = field(default_factory=dict)
    aggregate: dict[str, int] = field(default_factory=dict)
    reconciled: bool = False
    formula: str = (
        "raw_rows - (removed_unknown_label + removed_invalid + "
        "removed_exact_duplicates + removed_non_finite + removed_feature_duplicates + "
        "removed_label_conflicts) == final_modeling_rows"
    )

    def validate_reconciliation(self) -> None:
        """Verify mathematical identity: raw_total - sum(all_removed) == final_total."""
        agg = self.aggregate
        raw = agg.get("raw_rows", 0)
        removed = (
            agg.get("removed_unknown_label", 0)
            + agg.get("removed_invalid", 0)
            + agg.get("removed_exact_duplicates", 0)
            + agg.get("removed_non_finite", 0)
            + agg.get("removed_feature_duplicates", 0)
            + agg.get("removed_label_conflicts", 0)
        )
        final = agg.get("final_modeling_rows", 0)

        if (raw - removed) != final:
            raise AccountingReconciliationError(
                f"Accounting mathematical reconciliation FAILED: "
                f"raw_rows ({raw}) - total_removed ({removed}) = {raw - removed}, "
                f"but final_modeling_rows is {final}. Discrepancy: {final - (raw - removed)} rows."
            )
        self.reconciled = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PopulationConfig:
    """Declarative specification of the multi-file experiment population."""

    dataset: str
    files: list[str] | str = "all"  # "all" | "all_verified" | list of filenames
    exclude_files: list[str] = field(default_factory=list)
    file_order: str = "manifest"  # "manifest" | "as_specified" | "alphabetical"
    require_verified_checksums: bool = True
    require_schema_validated: bool = True
    duplicate_policy: str = "deduplicate_features"  # "deduplicate_features" | "retain"
    duplicate_conflict_policy: str = "reject_conflicts"  # "reject_conflicts" | "keep_first" | "preserve_separate"
    sample_limit: int | None = None  # None for full data; integer for developmental subsample
    sample_strategy: str = "stratified"
    seed: int = 42


@dataclass
class DatasetPopulation:
    """The fully prepared, auditable multi-file dataset population."""

    features: pd.DataFrame
    labels: pd.Series
    provenance: pd.DataFrame
    files: list[PopulationFileRecord]
    accounting: PopulationAccounting
    conflict_report: DuplicateConflictReport
    config: PopulationConfig
    feature_names: list[str]

    def to_manifest_dict(self) -> dict[str, Any]:
        """Produce machine-readable experiment_population.json manifest."""
        return {
            "dataset": self.config.dataset,
            "feature_contract": {
                "feature_count": len(self.feature_names),
                "features": self.feature_names,
            },
            "population_config": asdict(self.config),
            "files": [f.to_dict() for f in self.files],
            "accounting": self.accounting.to_dict(),
            "duplicate_conflict_analysis": self.conflict_report.to_dict(),
            "population_summary": {
                "total_modeling_rows": len(self.features),
                "benign_count": int((self.labels == 0).sum()),
                "attack_count": int((self.labels == 1).sum()),
                "attack_fraction": float((self.labels == 1).mean()) if len(self.labels) else 0.0,
                "attack_families": self.provenance["label_family"].value_counts().to_dict(),
                "rows_per_file": self.provenance["source_file"].value_counts().to_dict(),
            },
        }

    def write_manifest(self, path: str | Path) -> Path:
        """Write experiment_population.json to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_manifest_dict(), indent=2, default=str), encoding="utf-8")
        return target


def analyze_duplicate_label_conflicts(
    feature_df: pd.DataFrame,
    labels: pd.Series,
    provenance_df: pd.DataFrame,
    *,
    policy: str = "reject_conflicts",
    max_examples: int = 10,
) -> tuple[pd.Index, DuplicateConflictReport]:
    """Analyze identical feature vectors having conflicting ground truth labels.

    Returns
    -------
    tuple[pd.Index, DuplicateConflictReport]
        Indices to retain according to the selected policy, and the conflict audit report.
    """
    if len(feature_df) == 0:
        return feature_df.index, DuplicateConflictReport(policy_applied=policy)

    # Hash the feature vectors for fast, memory-safe duplicate detection
    h = pd.util.hash_pandas_object(feature_df, index=False)
    dupe_vector_mask = h.duplicated(keep=False)

    if not dupe_vector_mask.any():
        return feature_df.index, DuplicateConflictReport(policy_applied=policy)

    # Group duplicate hashes and examine labels
    dupe_hashes = h[dupe_vector_mask]
    dupe_labels = labels[dupe_vector_mask]
    dupe_families = provenance_df["label_family"][dupe_vector_mask]

    grouped = dupe_labels.groupby(dupe_hashes)
    nunique_labels = grouped.nunique()

    # Conflicting vectors have nunique > 1
    conflicting_hash_ids = nunique_labels[nunique_labels > 1].index
    n_conflicting_vectors = len(conflicting_hash_ids)

    # Count rows involved
    conflicting_mask = h.isin(conflicting_hash_ids)
    n_conflicting_rows = int(conflicting_mask.sum())

    benign_attack_conflicts = 0
    family_conflicts = 0
    conflict_examples: list[dict[str, Any]] = []

    if n_conflicting_vectors > 0:
        logger.warning(
            "DUPLICATE CONFLICT: Found %d conflicting feature vectors across %d rows (policy=%s)",
            n_conflicting_vectors,
            n_conflicting_rows,
            policy,
        )
        for h_val in conflicting_hash_ids[:max_examples]:
            sub_idx = h[h == h_val].index
            lbls = labels.loc[sub_idx].unique().tolist()
            fams = provenance_df.loc[sub_idx, "label_family"].unique().tolist()
            is_ba = (0 in lbls) and (1 in lbls)
            if is_ba:
                benign_attack_conflicts += 1
            if len(fams) > 1:
                family_conflicts += 1

            conflict_examples.append({
                "hash": int(h_val),
                "row_count": len(sub_idx),
                "binary_labels": [int(x) for x in lbls],
                "label_families": [str(x) for x in fams],
                "sample_indices": [int(x) for x in sub_idx[:3]],
            })

    # Apply policy
    if policy == "reject_conflicts":
        # Reject ALL rows belonging to conflicting vectors
        retain_indices = feature_df.index[~conflicting_mask]
        rows_dropped = n_conflicting_rows
    elif policy == "keep_first":
        # Keep first occurrence, log conflict
        retain_indices = feature_df.index
        rows_dropped = 0
    elif policy == "preserve_separate":
        # Reject from main modeling population so they can be saved in an analysis set
        retain_indices = feature_df.index[~conflicting_mask]
        rows_dropped = n_conflicting_rows
    else:
        raise ValueError(f"Unknown duplicate conflict policy: '{policy}'")

    report = DuplicateConflictReport(
        total_unique_vectors_with_duplicates=int(grouped.ngroups),
        total_conflicting_vectors=int(n_conflicting_vectors),
        total_conflicting_rows=int(n_conflicting_rows),
        benign_attack_conflicts=int(benign_attack_conflicts),
        family_conflicts=int(family_conflicts),
        policy_applied=policy,
        rows_dropped=int(rows_dropped),
        conflict_examples=conflict_examples,
    )
    return retain_indices, report


def load_dataset_population(
    config: PopulationConfig,
    feature_names: Sequence[str],
    *,
    contract: LabelContract,
    registry: FeatureRegistry,
    base_dir: str | Path = "data/raw",
    chunk_size: int = 100_000,
) -> DatasetPopulation:
    """Load, verify, clean, extract features, and reconcile a multi-file dataset population."""
    manifest = load_manifest()
    entry = next((d for d in manifest["datasets"] if d["key"] == config.dataset), None)
    if entry is None:
        raise DatasetIntegrityError(f"Dataset '{config.dataset}' is not registered in manifest.")

    raw_dir = Path(base_dir) / config.dataset
    registered_files = entry.get("files", [])
    if not registered_files:
        raise DatasetIntegrityError(f"No files registered in manifest for dataset '{config.dataset}'.")

    # 1. Resolve files to load
    target_filenames: list[str] = []
    if isinstance(config.files, str) and config.files in ("all", "all_verified"):
        target_filenames = [f["filename"] for f in registered_files if f.get("status") == "verified"]
    elif isinstance(config.files, list):
        target_filenames = list(config.files)
    else:
        raise ValueError(f"Invalid files specification: {config.files}")

    # Exclusions
    if config.exclude_files:
        target_filenames = [f for f in target_filenames if f not in config.exclude_files]

    if not target_filenames:
        raise DatasetIntegrityError(f"No matching verified files found for dataset '{config.dataset}'.")

    # Ordering
    if config.file_order == "alphabetical":
        target_filenames.sort()
    elif config.file_order == "as_specified":
        pass  # preserve list order
    else:  # "manifest"
        manifest_order = [f["filename"] for f in registered_files]
        target_filenames.sort(key=lambda fn: manifest_order.index(fn) if fn in manifest_order else 999)

    logger.info("loading multi-file population for %s (%d files)", config.dataset, len(target_filenames))

    # 2. Checksum and presence pre-flight on all files
    file_records: list[PopulationFileRecord] = []
    reg_lookup = {f["filename"]: f for f in registered_files}

    for fn in target_filenames:
        f_entry = reg_lookup.get(fn)
        if not f_entry:
            raise DatasetIntegrityError(f"File '{fn}' is not registered in manifest for '{config.dataset}'.")

        f_path = Path(f_entry["path"])
        if not f_path.is_file():
            f_path = raw_dir / fn
        if not f_path.is_file():
            raise FileNotFoundError(f"Physical file missing for registered file: {f_path}")

        if config.require_verified_checksums:
            actual_sha = sha256_file(f_path)
            if actual_sha != f_entry.get("sha256"):
                raise DatasetIntegrityError(
                    f"Checksum mismatch for '{fn}': expected {f_entry.get('sha256')}, got {actual_sha}"
                )

        file_records.append(
            PopulationFileRecord(
                filename=fn,
                relative_path=str(f_path),
                sha256=f_entry["sha256"],
                size_bytes=f_path.stat().st_size,
                raw_rows=0,  # will be populated during load
                provenance_class=entry.get("provenance_class", "unknown"),
                status="verified",
            )
        )

    # 3. Stream each file: clean -> extract features -> capture provenance -> record accounting
    all_features_chunks: list[pd.DataFrame] = []
    all_labels_chunks: list[pd.Series] = []
    all_prov_chunks: list[pd.DataFrame] = []

    per_file_accounting: dict[str, dict[str, int]] = {}
    total_raw_rows = 0
    total_removed_unknown = 0
    total_removed_invalid = 0
    total_removed_exact_dupes = 0
    total_removed_non_finite = 0
    global_row_counter = 0

    for f_rec in file_records:
        path = Path(f_rec.relative_path)
        logger.info("processing %s ...", path.name)

        # Read in chunks to remain memory-bounded
        raw_rows_this_file = 0
        file_removed_unknown = 0
        file_removed_invalid = 0
        file_removed_exact_dupes = 0
        file_removed_non_finite = 0
        file_final_modeling_rows = 0

        # We process chunk by chunk
        for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
            n_chunk_raw = len(chunk)
            raw_rows_this_file += n_chunk_raw

            # Determine raw label column name
            cand_cols = [c for c in chunk.columns if c.strip().lower() in ("label", "attack_cat")]
            raw_label_col = cand_cols[0] if cand_cols else chunk.columns[-1]

            # Extract label family prior to cleaning
            # For UNSW-NB15, attack_cat holds the family if present
            if config.dataset == "unsw_nb15" and "attack_cat" in chunk.columns:
                chunk_family_series = chunk["attack_cat"].astype(str).str.strip()
            else:
                chunk_family_series = chunk[raw_label_col].astype(str).str.strip()

            chunk_row_indices = np.arange(global_row_counter, global_row_counter + n_chunk_raw)
            global_row_counter += n_chunk_raw

            # Clean frame (handles label normalization, unknown-label rejection, negative duration, exact dupes)
            cleaned = clean_dataset_frame(chunk, config.dataset, contract)
            acct = cleaned.accounting

            n_clean = len(cleaned.frame)
            file_removed_unknown += acct["removed_unknown_label"]
            file_removed_invalid += acct["removed_invalid"]
            file_removed_exact_dupes += acct["removed_duplicates"]

            if n_clean == 0:
                continue

            # Align family series with accepted indices
            accepted_indices = cleaned.frame.index
            clean_families = chunk_family_series.iloc[accepted_indices].reset_index(drop=True)
            clean_source_rows = pd.Series(accepted_indices, name="source_row_index")
            clean_global_orders = pd.Series(chunk_row_indices[accepted_indices], name="original_order")

            # Extract semantic fields & compute features
            semantics, _ = extract_semantics(cleaned.frame, config.dataset, registry, strict=True)
            feat_matrix, avail, unavail = compute_features(
                semantics, feature_names, dataset=config.dataset, strict=False
            )
            feat_df = feat_matrix[avail].astype(np.float32)

            # Filter non-finite (NaN / Inf)
            finite_mask = np.isfinite(feat_df.to_numpy(dtype=np.float32)).all(axis=1)
            n_finite = int(finite_mask.sum())
            n_non_finite = len(feat_df) - n_finite
            file_removed_non_finite += n_non_finite

            if n_finite == 0:
                continue

            feat_df = feat_df.loc[finite_mask].reset_index(drop=True)
            chunk_labels = cleaned.labels.binary.loc[finite_mask].reset_index(drop=True)
            chunk_canonical = cleaned.labels.canonical.loc[finite_mask].reset_index(drop=True)
            chunk_families = clean_families.loc[finite_mask].reset_index(drop=True)
            chunk_src_rows = clean_source_rows.loc[finite_mask].reset_index(drop=True)
            chunk_gl_orders = clean_global_orders.loc[finite_mask].reset_index(drop=True)

            file_final_modeling_rows += n_finite

            # Build provenance DataFrame for this chunk
            chunk_prov = pd.DataFrame({
                "dataset": config.dataset,
                "source_file": path.name,
                "source_row_index": chunk_src_rows,
                "original_order": chunk_gl_orders,
                "label_family": chunk_families,
                "canonical_label": chunk_canonical,
                "binary_label": chunk_labels,
                "split_membership": "unassigned",
            })

            all_features_chunks.append(feat_df)
            all_labels_chunks.append(chunk_labels)
            all_prov_chunks.append(chunk_prov)

        f_rec.raw_rows = raw_rows_this_file
        f_rec.accounting = {
            "raw_rows": raw_rows_this_file,
            "removed_unknown_label": file_removed_unknown,
            "removed_invalid": file_removed_invalid,
            "removed_exact_duplicates": file_removed_exact_dupes,
            "removed_non_finite": file_removed_non_finite,
            "final_modeling_rows": file_final_modeling_rows,
        }
        per_file_accounting[f_rec.filename] = f_rec.accounting

        total_raw_rows += raw_rows_this_file
        total_removed_unknown += file_removed_unknown
        total_removed_invalid += file_removed_invalid
        total_removed_exact_dupes += file_removed_exact_dupes
        total_removed_non_finite += file_removed_non_finite

    # 4. Concatenate populations
    if not all_features_chunks:
        raise ValueError(f"No valid modeling rows extracted across {len(file_records)} files.")

    combined_features = pd.concat(all_features_chunks, ignore_index=True)
    combined_labels = pd.concat(all_labels_chunks, ignore_index=True)
    combined_prov = pd.concat(all_prov_chunks, ignore_index=True)

    # 5. Feature-space deduplication & Conflict Analysis
    total_removed_feature_dupes = 0
    total_removed_conflicts = 0
    conflict_report = DuplicateConflictReport(policy_applied=config.duplicate_conflict_policy)

    if config.duplicate_policy == "deduplicate_features":
        # First resolve conflicts
        retain_idx, conflict_report = analyze_duplicate_label_conflicts(
            combined_features,
            combined_labels,
            combined_prov,
            policy=config.duplicate_conflict_policy,
        )
        total_removed_conflicts = conflict_report.rows_dropped

        if len(retain_idx) < len(combined_features):
            combined_features = combined_features.loc[retain_idx].reset_index(drop=True)
            combined_labels = combined_labels.loc[retain_idx].reset_index(drop=True)
            combined_prov = combined_prov.loc[retain_idx].reset_index(drop=True)

        # Then deduplicate remaining identical feature vectors (Policy A)
        h = pd.util.hash_pandas_object(combined_features, index=False)
        is_feat_dupe = h.duplicated(keep="first")
        n_feat_dupes = int(is_feat_dupe.sum())
        total_removed_feature_dupes = n_feat_dupes

        if n_feat_dupes > 0:
            logger.info("deduplicating %d identical feature vectors", n_feat_dupes)
            combined_features = combined_features.loc[~is_feat_dupe].reset_index(drop=True)
            combined_labels = combined_labels.loc[~is_feat_dupe].reset_index(drop=True)
            combined_prov = combined_prov.loc[~is_feat_dupe].reset_index(drop=True)

    # 6. Optional developmental subsample limit (strictly tagged)
    if config.sample_limit and config.sample_limit < len(combined_features):
        logger.warning(
            "DEVELOPMENT_ONLY: Applying sample limit %d on %d rows",
            config.sample_limit,
            len(combined_features),
        )
        rng = np.random.default_rng(config.seed)
        sample_indices: list[int] = []
        frac = min(1.0, float(config.sample_limit / len(combined_features)))
        for label_val in (0, 1):
            subset = np.where(combined_labels == label_val)[0]
            n_sub = max(1, int(round(len(subset) * frac)))
            chosen = rng.choice(subset, size=min(len(subset), n_sub), replace=False)
            sample_indices.extend(chosen)
        sample_indices.sort()

        combined_features = combined_features.iloc[sample_indices].reset_index(drop=True)
        combined_labels = combined_labels.iloc[sample_indices].reset_index(drop=True)
        combined_prov = combined_prov.iloc[sample_indices].reset_index(drop=True)

    # 7. Construct and validate complete accounting
    aggregate_accounting = {
        "raw_rows": total_raw_rows,
        "removed_unknown_label": total_removed_unknown,
        "removed_invalid": total_removed_invalid,
        "removed_exact_duplicates": total_removed_exact_dupes,
        "removed_non_finite": total_removed_non_finite,
        "removed_feature_duplicates": total_removed_feature_dupes,
        "removed_label_conflicts": total_removed_conflicts,
        "final_modeling_rows": len(combined_features),
    }

    accounting = PopulationAccounting(
        per_file=per_file_accounting,
        aggregate=aggregate_accounting,
    )
    if config.sample_limit is None:
        accounting.validate_reconciliation()
    else:
        accounting.reconciled = False

    return DatasetPopulation(
        features=combined_features,
        labels=combined_labels,
        provenance=combined_prov,
        files=file_records,
        accounting=accounting,
        conflict_report=conflict_report,
        config=config,
        feature_names=list(feature_names),
    )
