"""Canonical column-header normalization — the single column contract.

CICFlowMeter exports headers with leading/trailing spaces (``" Flow Duration"``),
occasional embedded newlines/carriage returns, and other export artefacts. Historically
the schema validator compared *raw* headers while cleaning *stripped* them, so the two
disagreed and CIC-IDS2017 feature extraction could never succeed.

This module defines ONE rule and every stage uses it:

    raw header  --canonicalize_column()-->  canonical header  -->  matching

Rules (deterministic, order-independent, lossless with respect to provenance):

1. Unicode NFKC normalisation (folds full-width/compatibility characters),
2. carriage returns / newlines / tabs become spaces,
3. leading and trailing whitespace is stripped,
4. internal whitespace runs collapse to a single space,
5. case is **preserved** (case-insensitive matching would hide real schema errors).

Raw headers are never destroyed: callers keep them for provenance and report both
original and canonical names. Two distinct raw headers that canonicalize to the same
string are a hard error — silently picking one would corrupt the column contract.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable, Sequence

import pandas as pd

_WS_RUN = re.compile(r"\s+")


class ColumnNormalizationError(ValueError):
    """Raised when a header cannot be canonicalized unambiguously."""


def canonicalize_column(name: object) -> str:
    """Return the canonical form of one column header.

    ``canonicalize_column`` is idempotent: ``canonicalize_column(canonicalize_column(x))
    == canonicalize_column(x)`` for every input.
    """
    if name is None:
        raise ColumnNormalizationError("column name is None")
    text = unicodedata.normalize("NFKC", str(name))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.strip()
    text = _WS_RUN.sub(" ", text)
    return text


def canonicalize_columns(names: Iterable[object]) -> list[str]:
    """Canonicalize a header list, failing loudly on canonical-name collisions."""
    out: list[str] = []
    seen: dict[str, object] = {}
    for raw in names:
        canon = canonicalize_column(raw)
        if not canon:
            raise ColumnNormalizationError(f"column {raw!r} canonicalizes to an empty name")
        if canon in seen and seen[canon] != raw:
            raise ColumnNormalizationError(
                f"two distinct headers {seen[canon]!r} and {raw!r} both canonicalize to "
                f"{canon!r}; the column contract would be ambiguous"
            )
        seen.setdefault(canon, raw)
        out.append(canon)
    return out


def raw_to_canonical_map(raw_columns: Sequence[object]) -> dict[str, str]:
    """Map each raw header to its canonical name (for provenance reporting)."""
    return {str(raw): canonicalize_column(raw) for raw in raw_columns}


def canonicalize_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a frame with canonical headers, preserving raw headers in ``attrs``.

    The original headers are recorded under ``attrs['raw_columns']`` (in original
    order) and ``attrs['raw_to_canonical']`` so audit artifacts can show both.
    """
    raw = [str(c) for c in frame.columns]
    canon = canonicalize_columns(raw)
    out = frame.copy(deep=False)
    out.columns = canon
    out.attrs["raw_columns"] = raw
    out.attrs["raw_to_canonical"] = raw_to_canonical_map(raw)
    return out
