"""Deterministic cleaning pipeline with row accounting (build spec sections 11, 13).

Every operation is measured and recorded as BEFORE / AFTER / REMOVED / RETAINED /
REASON, and the accounting must reconcile exactly. No row disappears without a reason.

Design notes
------------
* Vendor rate columns frequently contain Infinity. We deliberately do not patch them
  here: the canonical features RECOMPUTE rates from source quantities, so those columns
  are never model inputs. This is the historical "recompute rather than replace" decision.
* Extreme values are NOT deleted merely for being extreme. Unusual is not invalid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from xrlids.labels.contract import LabelContract, apply_label_contract
from xrlids.labels.contract import LabelApplication
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class CleaningAccountingError(RuntimeError):
    """Raised when row accounting does not reconcile."""


@dataclass
class CleaningStep:
    operation: str
    before: int
    after: int
    reason: str
    detection: str = ""
    risk: str = ""
    alternative: str = ""

    @property
    def removed(self) -> int:
        return self.before - self.after

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "before": self.before,
            "after": self.after,
            "removed": self.removed,
            "retained": self.after,
            "reason": self.reason,
            "detection": self.detection,
            "risk": self.risk,
            "alternative": self.alternative,
        }


@dataclass
class CleanedDataset:
    """Cleaned frame plus labels, accounting and the rejection report."""

    frame: pd.DataFrame
    labels: LabelApplication
    steps: list[CleaningStep]
    accounting: dict[str, int]
    rejection_summary: pd.DataFrame
    dataset: str
    extra: dict[str, Any] = field(default_factory=dict)

    def accounting_report(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "steps": [s.to_dict() for s in self.steps],
            "accounting": dict(self.accounting),
        }


def _strip_column_names(frame: pd.DataFrame) -> pd.DataFrame:
    out = frame.copy()
    out.columns = [str(c).strip() for c in out.columns]
    return out


def clean_dataset_frame(
    raw_frame: pd.DataFrame,
    dataset: str,
    contract: LabelContract,
    *,
    duration_column_candidates: tuple[str, ...] = ("Flow Duration", "dur"),
    duration_scale: float = 1.0,
    label_column: str | None = None,
    drop_exact_duplicates: bool = True,
    drop_negative_duration: bool = True,
) -> CleanedDataset:
    """Clean one dataset file and reconcile the row accounting.

    The returned frame keeps all original columns; feature extraction happens later on
    the cleaned frame, so nothing here depends on the feature registry.
    """
    steps: list[CleaningStep] = []
    frame = _strip_column_names(raw_frame)
    raw_rows = len(frame)
    rows_at_start = raw_rows

    # -- 1. exact duplicate rows ------------------------------------------------
    if drop_exact_duplicates:
        before = len(frame)
        frame = frame.drop_duplicates(keep="first")
        steps.append(
            CleaningStep(
                operation="drop_exact_duplicate_rows",
                before=before,
                after=len(frame),
                reason="byte-identical feature rows carry no additional information "
                       "and are a known leakage vector across splits",
                detection="DataFrame.drop_duplicates(keep='first')",
                risk="duplicate removal may preferentially hit one class and shift class balance",
                alternative="retain duplicates and instead prevent cross-split duplication in the splitter",
            )
        )

    # -- 2. unknown / unmapped labels -------------------------------------------
    labels = apply_label_contract(frame, dataset, contract, label_column=label_column)
    before = len(frame)
    frame = frame.loc[labels.accepted_mask].copy()
    labels_kept = LabelApplication(
        canonical=labels.canonical.loc[frame.index],
        binary=labels.binary.loc[frame.index],
        family=labels.family.loc[frame.index],
        native=labels.native.loc[frame.index],
        normalized=labels.normalized.loc[frame.index],
        accepted_mask=labels.accepted_mask.loc[frame.index],
        rejections=labels.rejections,
        stats=labels.stats,
    )
    steps.append(
        CleaningStep(
            operation="reject_unknown_labels",
            before=before,
            after=len(frame),
            reason="labels not declared benign and not in the dataset's known-attack "
                   "allow-list are UNKNOWN; they are rejected, never relabelled BENIGN",
            detection="xrlids.labels.contract.apply_label_contract",
            risk="a label typo in the contract would reject real attack rows; the audit "
                 "surfaces this as an unexpected rejection count",
            alternative="map unknowns to ATTACK (would inflate recall) or BENIGN (forbidden)",
        )
    )

    # -- 3. invalid (negative) durations ----------------------------------------
    if drop_negative_duration:
        duration_col = next((c for c in duration_column_candidates if c in frame.columns), None)
        if duration_col is not None:
            duration = pd.to_numeric(frame[duration_col], errors="coerce") * duration_scale
            invalid = duration < 0
            before = len(frame)
            frame = frame.loc[~invalid].copy()
            labels_kept = _reindex_labels(labels_kept, frame.index)
            steps.append(
                CleaningStep(
                    operation="drop_negative_duration",
                    before=before,
                    after=len(frame),
                    reason="a negative flow duration is physically impossible; the rate "
                           "features derived from it would be meaningless",
                    detection=f"{duration_col} < 0",
                    risk="if the column is actually unsigned and overflowed, dropping hides a parse bug",
                    alternative="take absolute value (rejected: masks data corruption)",
                )
            )

    # -- reconcile ---------------------------------------------------------------
    removed = sum(s.removed for s in steps)
    accounting = {
        "raw_rows_at_start": rows_at_start,
        "removed_duplicates": next((s.removed for s in steps if s.operation == "drop_exact_duplicate_rows"), 0),
        "removed_unknown_label": next((s.removed for s in steps if s.operation == "reject_unknown_labels"), 0),
        "removed_invalid": next((s.removed for s in steps if s.operation == "drop_negative_duration"), 0),
        "recovered_rows": 0,
        "final_accepted_rows": len(frame),
        "total_removed": removed,
    }
    if accounting["raw_rows_at_start"] - removed != accounting["final_accepted_rows"]:
        raise CleaningAccountingError(
            "row accounting does not reconcile: "
            f"{accounting['raw_rows_at_start']} - {removed} != {accounting['final_accepted_rows']}"
        )

    rejection_summary = _rejection_summary(accounting, labels.rejections, dataset)

    logger.info(
        "cleaned dataset=%s raw=%d accepted=%d removed=%d",
        dataset,
        accounting["raw_rows_at_start"],
        accounting["final_accepted_rows"],
        removed,
    )

    return CleanedDataset(
        frame=frame,
        labels=labels_kept,
        steps=steps,
        accounting=accounting,
        rejection_summary=rejection_summary,
        dataset=dataset,
    )


def _reindex_labels(labels: LabelApplication, index: pd.Index) -> LabelApplication:
    return LabelApplication(
        canonical=labels.canonical.loc[index],
        binary=labels.binary.loc[index],
        family=labels.family.loc[index],
        native=labels.native.loc[index],
        normalized=labels.normalized.loc[index],
        accepted_mask=labels.accepted_mask.loc[index],
        rejections=labels.rejections,
        stats=labels.stats,
    )


def _rejection_summary(
    accounting: dict[str, int], rejections: pd.DataFrame, dataset: str
) -> pd.DataFrame:
    rows = [
        {"dataset": dataset, "category": "duplicate_rows", "row_count": accounting["removed_duplicates"], "reason": "exact duplicate row"},
        {"dataset": dataset, "category": "invalid_rows", "row_count": accounting["removed_invalid"], "reason": "negative duration"},
    ]
    if not rejections.empty:
        for _, r in rejections.iterrows():
            rows.append(
                {
                    "dataset": dataset,
                    "category": "unknown_label",
                    "original_label": r["original_label"],
                    "normalized_label": r["normalized_label"],
                    "row_count": int(r["row_count"]),
                    "percentage": float(r["percentage"]),
                    "reason": r["reason"],
                }
            )
    return pd.DataFrame(rows)
