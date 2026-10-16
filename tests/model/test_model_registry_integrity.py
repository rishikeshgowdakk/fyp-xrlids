"""Integrity tests for the canonical model artifact registry.

These tests guarantee that the metadata committed in
``models/registry/model_manifest.json`` and ``models/registry/registry.yaml``
stays in sync with the actual artifact bytes and with each other.

Model binaries are gitignored (see ``.gitignore``), so the checksum comparison
is skipped when a canonical artifact file is not present on disk. The
registry-vs-registry consistency checks always run.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "models/registry/model_manifest.json"
REGISTRY_PATH = REPO_ROOT / "models/registry/registry.yaml"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry() -> dict:
    return yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_registries_declare_the_same_models(manifest, registry):
    assert registry["canonical_models_count"] == manifest["canonical_models_count"]
    assert manifest["canonical_models_count"] == len(manifest["artifacts"])

    manifest_ids = {a["model_id"] for a in manifest["artifacts"]}
    registry_ids = {a["model_id"] for a in registry["artifacts"]}
    assert manifest_ids == registry_ids


def test_registries_report_identical_metadata(manifest, registry):
    by_id = {a["model_id"]: a for a in registry["artifacts"]}
    for artifact in manifest["artifacts"]:
        peer = by_id[artifact["model_id"]]
        for field in ("canonical_path", "sha256", "size_bytes", "model_type"):
            assert artifact[field] == peer[field], (
                f"{artifact['model_id']}: {field} differs between manifest and registry"
            )
        if "test_f1" in artifact:
            assert artifact["test_f1"] == peer.get("test_f1")


def test_declared_checksums_are_well_formed(manifest):
    for artifact in manifest["artifacts"]:
        sha = artifact["sha256"]
        assert len(sha) == 64, f"{artifact['model_id']}: checksum must be 64 hex chars"
        assert all(c in "0123456789abcdef" for c in sha), (
            f"{artifact['model_id']}: checksum must be lowercase hex"
        )


@pytest.mark.parametrize("dataset_key", ["unsw_nb15"])
def test_degraded_contract_is_labelled_correctly(registry, dataset_key):
    """UNSW-NB15 runs the R4 fallback contract, never R10."""
    unsw = [a for a in registry["artifacts"] if a.get("dataset") == dataset_key]
    assert unsw, "expected UNSW-NB15 artifacts in the registry"
    for artifact in unsw:
        assert artifact["feature_contract"] == "R4", (
            f"{artifact['model_id']}: expected R4 fallback contract"
        )


def test_present_artifacts_match_recorded_checksum(manifest):
    present = 0
    for artifact in manifest["artifacts"]:
        path = REPO_ROOT / artifact["canonical_path"]
        if not path.exists():
            continue  # gitignored binary absent; nothing to verify on disk
        present += 1
        assert path.stat().st_size == artifact["size_bytes"], (
            f"{artifact['model_id']}: size_bytes is stale"
        )
        assert _sha256(path) == artifact["sha256"], (
            f"{artifact['model_id']}: SHA-256 mismatch — registry is stale"
        )
    if present == 0:
        pytest.skip("no canonical model artifacts on disk to verify")
