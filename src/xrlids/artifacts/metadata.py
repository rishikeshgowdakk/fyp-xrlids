"""Artifact metadata (build spec section 38).

Rule: a model file must never exist without corresponding metadata. Every result
artifact therefore carries an experiment id, Git commit, dataset checksum, feature
schema hash, seed, timestamp, environment fingerprint and artifact version.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from xrlids.utils.env import environment_fingerprint

ARTIFACT_VERSION = "1"


@dataclass(frozen=True)
class ArtifactMetadata:
    """Reproducibility metadata attached to every generated artifact."""

    experiment_id: str
    git_commit: str | None = None
    dataset_sha256: str | None = None
    feature_schema_hash: str | None = None
    seed: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    software_environment: dict[str, Any] = field(default_factory=environment_fingerprint)
    artifact_version: str = ARTIFACT_VERSION
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_json_artifact(
    path: str | Path,
    payload: dict[str, Any],
    metadata: ArtifactMetadata,
    *,
    write_sidecar: bool = True,
) -> Path:
    """Write ``payload`` as JSON, optionally alongside a ``*.meta.json`` sidecar.

    Machine-readable results are the source of truth; Markdown reports are generated
    from them (build spec section 28).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"metadata": metadata.to_dict(), **payload}
    path.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")

    if write_sidecar:
        sidecar = path.with_suffix(path.suffix + ".meta.json")
        sidecar.write_text(json.dumps(metadata.to_dict(), indent=2, default=str), encoding="utf-8")
    return path
