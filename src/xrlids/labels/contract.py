"""Label contract implementation (build spec sections 7, 14; scientific RULE 3).

The contract turns a raw dataset label into:

    native label  ->  normalized label  ->  canonical {BENIGN, ATTACK}  ->  attack family

Anything that is neither a declared benign label nor a declared known attack label is
UNKNOWN and is REJECTED with accounting. It is never silently relabelled BENIGN.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import pandas as pd
import yaml


class UnknownLabelError(ValueError):
    """Raised when labels cannot be reconciled with the contract.

    Carries the offending labels and counts so the failure is actionable rather than
    a bare string.
    """

    def __init__(self, message: str, *, unknown: dict[str, int] | None = None):
        super().__init__(message)
        self.unknown = unknown or {}


class InvalidReplacementTableError(ValueError):
    """Raised when the configured unicode replacement table is unsafe.

    A replacement table is applied with ``str.replace`` BEFORE any other normalisation.
    An empty key (``"" -> "-"``) therefore inserts its value between every character and
    silently corrupts every label (``"BENIGN"`` becomes ``"-B-E-N-I-G-N-"``). Such
    tables must fail loudly at contract-load time instead of corrupting data quietly.
    """


_WS = re.compile(r"\s+")


def validate_replacements(replacements: object) -> dict[str, str]:
    """Validate a unicode replacement table, returning it unchanged when safe.

    Rules (each one exists because of a defect that was actually observed or is a
    one-character variation of it):

    1. the table must be a mapping of strings to strings,
    2. keys must be non-empty and not whitespace-only (empty key = per-character corruption),
    3. a key must not be a single ASCII alphanumeric or space — replacing those
       character-by-character destroys text (this is the "BENIGN" -> "-B-E-N-I-G-N-" bug),
    4. a key must not be longer than 32 characters (a normalisation key is an artefact,
       not a sentence; a long key indicates a paste error),
    5. key == value is a no-op that indicates a configuration mistake.
    """
    if replacements is None:
        return {}
    if not isinstance(replacements, Mapping):
        raise InvalidReplacementTableError(
            f"unicode_replacements must be a mapping, got {type(replacements).__name__}"
        )
    validated: dict[str, str] = {}
    for key, value in replacements.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise InvalidReplacementTableError(
                f"replacement entries must be strings, got {key!r}: {value!r}"
            )
        if key == "" or key.strip() == "":
            raise InvalidReplacementTableError(
                "replacement key must not be empty or whitespace-only: an empty key is "
                "inserted between every character by str.replace and corrupts all labels "
                f"(offending key {key!r} -> {value!r})"
            )
        if len(key) == 1 and key.isascii() and (key.isalnum() or key.isspace()):
            raise InvalidReplacementTableError(
                f"replacement key {key!r} is a single ASCII character; replacing it "
                "character-by-character would corrupt text. Map the full artefact "
                "instead of one character."
            )
        if len(key) > 32:
            raise InvalidReplacementTableError(
                f"replacement key {key!r} is {len(key)} characters long; a normalisation "
                "key must be a short artefact, not a sentence"
            )
        if key == value:
            raise InvalidReplacementTableError(
                f"replacement {key!r} maps to itself; this is a configuration mistake"
            )
        validated[key] = value
    return validated


def normalize_label(value: Any, *, replacements: dict[str, str], strip_chars: str) -> str:
    """Normalize a raw label to a comparable canonical token.

    Steps: coerce to str, unicode-normalize (NFKC), apply configured replacements,
    strip configured characters, collapse internal whitespace, uppercase.
    """
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    text = text.strip(strip_chars)
    text = _WS.sub(" ", text)
    return text.upper()


@dataclass
class LabelContract:
    """Validated label contract loaded from ``configs/labels/label_mapping.yaml``."""

    raw: dict[str, Any]
    benign_tokens: set[str]
    datasets: dict[str, dict[str, Any]]
    replacements: dict[str, str]
    strip_chars: str
    attack_families: list[str]
    version: str = "0.0.0"
    status: str = "unknown"

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_file(cls, path: str | Path) -> "LabelContract":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        binary = data.get("binary", {})
        normalization = data.get("normalization", {})
        # Fail loudly on an unsafe replacement table BEFORE it can corrupt any label.
        replacements = validate_replacements(normalization.get("unicode_replacements"))
        strip_chars = normalization.get("strip_characters", " \t\r\n")
        if not isinstance(strip_chars, str) or not strip_chars:
            raise InvalidReplacementTableError(
                f"strip_characters must be a non-empty string, got {strip_chars!r}"
            )
        benign = {
            normalize_label(t, replacements={}, strip_chars="")
            for t in binary.get("benign_tokens", [])
        }
        if not benign:
            raise UnknownLabelError("contract declares no benign tokens; refusing to load")
        return cls(
            raw=data,
            benign_tokens=benign,
            datasets=data.get("datasets", {}),
            replacements=replacements,
            strip_chars=strip_chars,
            attack_families=data.get("attack_families", []),
            version=str(data.get("contract_version", "0.0.0")),
            status=str(data.get("status", "unknown")),
        )

    # ------------------------------------------------------------------- lookup
    def normalize(self, value: Any) -> str:
        return normalize_label(
            value, replacements=self.replacements, strip_chars=self.strip_chars
        )

    def _dataset_spec(self, dataset: str) -> dict[str, Any]:
        if dataset not in self.datasets:
            raise KeyError(
                f"dataset '{dataset}' is not declared in the label contract "
                f"(known: {sorted(self.datasets)})"
            )
        return self.datasets[dataset]

    def is_benign(self, normalized: str, dataset: str) -> bool:
        spec = self._dataset_spec(dataset)
        tokens = {self.normalize(t) for t in spec.get("benign_labels", [])}
        tokens |= self.benign_tokens
        return normalized in tokens

    def family_of(self, normalized: str, dataset: str) -> str:
        spec = self._dataset_spec(dataset)
        family_map = {self.normalize(k): v for k, v in (spec.get("family_map") or {}).items()}
        if normalized in family_map:
            family = family_map[normalized]
            if family in self.attack_families:
                return family
            return "Other"
        raise UnknownLabelError(f"label '{normalized}' has no family mapping for '{dataset}'")

    def classify(self, normalized: str, dataset: str) -> tuple[str, int]:
        """Return ``(canonical, binary)`` or raise :class:`UnknownLabelError`."""
        if not normalized:
            raise UnknownLabelError("empty label; cannot classify")
        if self.is_benign(normalized, dataset):
            return "BENIGN", 0
        spec = self._dataset_spec(dataset)
        family_map = {self.normalize(k): v for k, v in (spec.get("family_map") or {}).items()}
        if normalized in family_map:
            return "ATTACK", 1
        raise UnknownLabelError(
            f"label '{normalized}' is neither declared benign nor a known attack "
            f"for dataset '{dataset}'"
        )

    def is_known_attack(self, normalized: str, dataset: str) -> bool:
        spec = self._dataset_spec(dataset)
        family_map = {self.normalize(k): v for k, v in (spec.get("family_map") or {}).items()}
        return normalized in family_map and not self.is_benign(normalized, dataset)


def load_label_contract(path: str | Path = "configs/labels/label_mapping.yaml") -> LabelContract:
    return LabelContract.from_file(path)


@dataclass
class LabelApplication:
    """Outcome of applying the contract: accepted rows plus rejection accounting."""

    canonical: pd.Series
    binary: pd.Series
    family: pd.Series
    native: pd.Series
    normalized: pd.Series
    accepted_mask: pd.Series
    rejections: pd.DataFrame
    stats: dict[str, Any] = field(default_factory=dict)


def apply_label_contract(
    frame: pd.DataFrame,
    dataset: str,
    contract: LabelContract,
    *,
    label_column: str | None = None,
) -> LabelApplication:
    """Apply the contract to a dataframe, rejecting unknown labels with accounting.

    Never mutates the input frame. Unknown labels do not raise here: they are collected,
    counted and masked out, because rejection accounting is a required output. The
    *caller* decides whether the rejected fraction is acceptable.
    """
    spec = contract._dataset_spec(dataset)

    if label_column is None:
        # Canonical column contract: candidates are matched in canonical form so a raw
        # header like " Label" resolves to the same column after canonicalisation.
        from xrlids.utils.columns import canonicalize_column

        canon_columns = {canonicalize_column(c): c for c in frame.columns}
        for candidate in spec.get("label_column_candidates", []):
            hit = canon_columns.get(canonicalize_column(candidate))
            if hit is not None:
                label_column = hit
                break
    if label_column is None or label_column not in frame.columns:
        raise UnknownLabelError(
            f"could not resolve a label column for '{dataset}'. "
            f"candidates={spec.get('label_column_candidates')} "
            f"present={list(frame.columns)[:12]}..."
        )

    native = frame[label_column]
    normalized = native.map(contract.normalize)

    canonical: list[str] = []
    binary: list[int] = []
    family: list[str] = []
    accepted: list[bool] = []
    unknown_counts: dict[str, int] = {}

    for original, norm in zip(native, normalized):
        try:
            can, bit = contract.classify(norm, dataset)
        except UnknownLabelError:
            key = str(original)
            unknown_counts[key] = unknown_counts.get(key, 0) + 1
            canonical.append("UNKNOWN")
            binary.append(-1)
            family.append("UNKNOWN")
            accepted.append(False)
            continue
        fam = "BENIGN" if can == "BENIGN" else contract.family_of(norm, dataset)
        canonical.append(can)
        binary.append(bit)
        family.append(fam)
        accepted.append(True)

    total = len(frame)
    rejections = pd.DataFrame(
        [
            {
                "dataset": dataset,
                "original_label": original,
                "normalized_label": contract.normalize(original),
                "row_count": count,
                "percentage": round(100.0 * count / total, 6) if total else 0.0,
                "reason": "label not in benign tokens and not in declared known-attack allow-list",
            }
            for original, count in sorted(unknown_counts.items(), key=lambda kv: -kv[1])
        ]
    )

    raw_label_column = frame.attrs.get("canonical_to_raw", {}).get(label_column, label_column)
    stats = {
        "dataset": dataset,
        "label_column": raw_label_column,
        "label_column_canonical": canonicalize_column(label_column),
        "rows_total": int(total),
        "rows_accepted": int(sum(accepted)),
        "rows_rejected_unknown_label": int(total - sum(accepted)),
        "benign_rows": int(sum(1 for c in canonical if c == "BENIGN")),
        "attack_rows": int(sum(1 for c in canonical if c == "ATTACK")),
        "distinct_raw_labels": int(pd.Series(native).nunique(dropna=False)),
    }

    return LabelApplication(
        canonical=pd.Series(canonical, index=frame.index, name="canonical_label"),
        binary=pd.Series(binary, index=frame.index, name="binary_label", dtype="int64"),
        family=pd.Series(family, index=frame.index, name="attack_family"),
        native=native.rename("native_label"),
        normalized=normalized.rename("normalized_label"),
        accepted_mask=pd.Series(accepted, index=frame.index, name="label_accepted"),
        rejections=rejections,
        stats=stats,
    )
