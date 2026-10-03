"""Dataset isolation and policy-development split partitioning (Task 9).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 11:
    Phase 1 detector:
        frozen
    Policy-development population:
        designated policy-training portion (D_pol_train) (60%)
        designated policy-validation portion (D_pol_val) (40%)
    Final policy test population:
        completely untouched until final evaluation (D_pol_test)

Strict Anti-Leakage Protocol:
- The Phase 1 test population is strictly forbidden during Phase 2 development.
- No baseline thresholds, safety gate parameters, or policy hyperparameters
  may be tuned against D_pol_test.
- Row counts, hashes, and provenance must be fully documented.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from xrlids.utils.hashing import dict_hash


@dataclass
class PolicySplitManifest:
    """Documented record of the Phase 2 policy-development split."""

    dataset: str
    source_experiment_id: str
    phase1_validation_total_rows: int
    d_pol_train_rows: int
    d_pol_val_rows: int
    d_pol_test_untouched_rows: int
    d_pol_train_fraction: float = 0.60
    d_pol_val_fraction: float = 0.40
    seed: int = 42
    stratified: bool = True
    train_class_distribution: dict[str, Any] = None  # type: ignore
    val_class_distribution: dict[str, Any] = None    # type: ignore
    manifest_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def partition_policy_development_population(
    val_features: pd.DataFrame,
    val_labels: pd.Series,
    val_provenance: pd.DataFrame | None = None,
    *,
    dataset: str = "cicids2017",
    source_experiment_id: str = "EXP-P1-CIC2017-R10-001",
    phase1_test_row_count: int = 355865,
    train_fraction: float = 0.60,
    seed: int = 42,
) -> tuple[
    dict[str, pd.DataFrame],
    dict[str, pd.Series],
    dict[str, pd.DataFrame | None],
    PolicySplitManifest,
]:
    """Deterministically partition the Phase 1 validation population into D_pol_train and D_pol_val.

    Parameters
    ----------
    val_features: pd.DataFrame
        Phase 1 validation feature frame.
    val_labels: pd.Series
        Phase 1 validation binary label series.
    val_provenance: pd.DataFrame | None
        Optional provenance frame for validation flows.
    dataset: str
        Dataset identifier (e.g. 'cicids2017').
    source_experiment_id: str
        Parent Phase 1 experiment ID.
    phase1_test_row_count: int
        Untouched Phase 1 test row count (documented for provenance; NEVER loaded).
    train_fraction: float
        Fraction of validation population assigned to D_pol_train (default 0.60).
    seed: int
        Deterministic random seed.

    Returns
    -------
    features_splits, label_splits, provenance_splits, manifest
    """
    total_val_rows = len(val_features)
    if total_val_rows == 0:
        raise ValueError("Cannot partition empty validation population.")

    val_ratio = 1.0 - train_fraction
    indices = np.arange(total_val_rows)

    idx_train, idx_val = train_test_split(
        indices,
        test_size=val_ratio,
        random_state=seed,
        stratify=val_labels.values if len(np.unique(val_labels)) > 1 else None,
    )

    X_pol_train = val_features.iloc[idx_train].reset_index(drop=True)
    X_pol_val = val_features.iloc[idx_val].reset_index(drop=True)

    y_pol_train = val_labels.iloc[idx_train].reset_index(drop=True)
    y_pol_val = val_labels.iloc[idx_val].reset_index(drop=True)

    prov_train = val_provenance.iloc[idx_train].reset_index(drop=True) if val_provenance is not None else None
    prov_val = val_provenance.iloc[idx_val].reset_index(drop=True) if val_provenance is not None else None

    # Compute class distributions
    train_benign = int(np.sum(y_pol_train == 0))
    train_attack = int(np.sum(y_pol_train == 1))
    val_benign = int(np.sum(y_pol_val == 0))
    val_attack = int(np.sum(y_pol_val == 1))

    train_dist = {
        "benign": train_benign,
        "attack": train_attack,
        "attack_fraction": float(train_attack / max(1, len(y_pol_train))),
    }
    val_dist = {
        "benign": val_benign,
        "attack": val_attack,
        "attack_fraction": float(val_attack / max(1, len(y_pol_val))),
    }

    manifest_data = {
        "dataset": dataset,
        "source_experiment_id": source_experiment_id,
        "phase1_validation_total_rows": total_val_rows,
        "d_pol_train_rows": len(X_pol_train),
        "d_pol_val_rows": len(X_pol_val),
        "d_pol_test_untouched_rows": phase1_test_row_count,
        "d_pol_train_fraction": train_fraction,
        "d_pol_val_fraction": val_ratio,
        "seed": seed,
        "stratified": True,
        "train_class_distribution": train_dist,
        "val_class_distribution": val_dist,
    }
    m_hash = dict_hash(manifest_data)
    manifest = PolicySplitManifest(**manifest_data, manifest_hash=m_hash)

    features_splits = {"D_pol_train": X_pol_train, "D_pol_val": X_pol_val}
    label_splits = {"D_pol_train": y_pol_train, "D_pol_val": y_pol_val}
    provenance_splits = {"D_pol_train": prov_train, "D_pol_val": prov_val}

    return features_splits, label_splits, provenance_splits, manifest
