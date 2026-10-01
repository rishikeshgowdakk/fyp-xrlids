"""Experiment registry (build spec sections 27, 28, 38).

Every experiment gets a unique ID and a record that makes the question
"where did this number come from?" answerable:

    Experiment -> Config -> Dataset -> Split -> Preprocessor -> Model
               -> Predictions -> Metric -> Result -> Git commit
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact
from xrlids.utils.env import environment_fingerprint, git_commit
from xrlids.utils.hashing import dict_hash


def make_experiment_id(
    *,
    phase: int,
    model: str,
    dataset: str,
    rung: str,
    sequence: int,
) -> str:
    """Build an experiment ID, e.g. ``EXP-P1-RF-CIC-R10-001``."""
    model_token = re.sub(r"[^A-Z0-9]", "", model.upper())
    dataset_token = re.sub(r"[^A-Z0-9]", "", dataset.upper())
    rung_token = re.sub(r"[^A-Z0-9]", "", rung.upper())
    return f"EXP-P{phase}-{model_token}-{dataset_token}-{rung_token}-{sequence:03d}"


@dataclass
class ExperimentRecord:
    """The complete provenance record for one experiment."""

    experiment_id: str
    research_question: str
    hypothesis: str = ""
    dataset: str = ""
    dataset_sha256: str | None = None
    dataset_version: str | None = None
    input_files: list[str] = field(default_factory=list)
    rows_total: int | None = None
    rows_train: int | None = None
    rows_validation: int | None = None
    rows_test: int | None = None
    feature_contract: str = ""
    feature_list: list[str] = field(default_factory=list)
    feature_schema_hash: str | None = None
    preprocessing: dict[str, Any] = field(default_factory=dict)
    split_id: str | None = None
    model: dict[str, Any] = field(default_factory=dict)
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    random_seed: int | None = None
    threshold: float | None = None
    threshold_decision_id: str = "D-003"
    metrics: dict[str, Any] = field(default_factory=dict)
    confusion_matrix: dict[str, int] = field(default_factory=dict)
    training_duration_s: float | None = None
    hardware: str | None = None
    resource_profile: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    result_interpretation: str = ""
    limitations: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    git_commit: str | None = None
    software_environment: dict[str, Any] = field(default_factory=environment_fingerprint)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


def write_experiment_record(
    record: ExperimentRecord,
    path: str | Path,
) -> Path:
    """Write an experiment record as JSON with a reproducibility sidecar."""
    metadata = ArtifactMetadata(
        experiment_id=record.experiment_id,
        git_commit=record.git_commit or git_commit(),
        dataset_sha256=record.dataset_sha256,
        feature_schema_hash=record.feature_schema_hash,
        seed=record.random_seed,
        extra={"config_hash": dict_hash(record.to_dict().get("hyperparameters", {}))},
    )
    payload = record.to_dict()
    payload["git_commit"] = payload.get("git_commit") or git_commit()
    return write_json_artifact(path, payload, metadata)


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Load an experiment config, refusing an empty file."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not data:
        raise ValueError(f"config '{path}' is empty or invalid")
    return data
