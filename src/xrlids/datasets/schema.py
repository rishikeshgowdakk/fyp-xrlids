"""Schema validation of the feature-contract column maps against real files.

Reading only the header row of each CSV is cheap even for multi-GB files, so this can
validate every declared mapping against every real file as soon as data is placed -
before any full audit or training run. A column map that references a column absent from
the real file is a contract bug and must be reported, not papered over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from xrlids.features.registry import FeatureRegistry


class SchemaValidationError(RuntimeError):
    """Raised when a real file's schema contradicts the declared column map."""


@dataclass
class FileSchemaReport:
    path: str
    columns: list[str]
    n_columns: int
    declared_columns: list[str]
    missing: list[str]
    label_column_found: str | None
    extra_note: str = ""

    @property
    def ok(self) -> bool:
        return not self.missing


def read_header(path: str | Path) -> list[str]:
    """Read only the header row of a CSV."""
    return list(pd.read_csv(path, nrows=0).columns)


def _declared_columns_for_dataset(
    registry: FeatureRegistry, dataset: str
) -> list[str]:
    mapping = registry.column_maps.get(dataset, {})
    declared: list[str] = []
    for spec in mapping.values():
        if "column" in spec:
            declared.append(spec["column"])
        elif "sum" in spec:
            declared.extend(spec["sum"])
            declared.extend(spec["divide_by_sum"])
    return sorted(set(declared))


def validate_file_schema(
    path: str | Path,
    dataset: str,
    registry: FeatureRegistry,
    *,
    label_candidates: list[str] | None = None,
) -> FileSchemaReport:
    """Validate one real file's header against the dataset's declared column map."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    columns = read_header(path)
    declared = _declared_columns_for_dataset(registry, dataset)
    missing = [c for c in declared if c not in columns]

    label_found = None
    for candidate in label_candidates or []:
        if candidate in columns:
            label_found = candidate
            break

    return FileSchemaReport(
        path=str(path),
        columns=columns,
        n_columns=len(columns),
        declared_columns=declared,
        missing=missing,
        label_column_found=label_found,
    )


@dataclass
class DatasetSchemaReport:
    dataset: str
    files: list[FileSchemaReport] = field(default_factory=list)
    files_identical_schema: bool | None = None

    @property
    def ok(self) -> bool:
        return bool(self.files) and all(f.ok for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        column_sets = {tuple(f.columns) for f in self.files}
        return {
            "dataset": self.dataset,
            "n_files": len(self.files),
            "all_declared_columns_present": self.ok,
            "files_identical_schema": (
                len(column_sets) == 1 if self.files else None
            ),
            "label_columns_found": [
                {"file": f.path, "label_column": f.label_column_found} for f in self.files
            ],
            "files": [
                {
                    "path": f.path,
                    "n_columns": f.n_columns,
                    "missing_declared_columns": f.missing,
                    "label_column": f.label_column_found,
                }
                for f in self.files
            ],
        }


def validate_dataset_schema(
    directory: str | Path,
    dataset: str,
    registry: FeatureRegistry,
    *,
    label_candidates: list[str] | None = None,
    pattern: str = "*.csv",
) -> DatasetSchemaReport:
    """Validate every CSV in a dataset directory against the declared column map."""
    directory = Path(directory)
    if not directory.is_dir():
        raise SchemaValidationError(
            f"dataset directory not found: {directory} (dataset not acquired?)"
        )
    files = sorted(directory.glob(pattern))
    if not files:
        raise SchemaValidationError(f"no {pattern} files in {directory}")

    report = DatasetSchemaReport(dataset=dataset)
    for path in files:
        report.files.append(
            validate_file_schema(path, dataset, registry, label_candidates=label_candidates)
        )
    return report
