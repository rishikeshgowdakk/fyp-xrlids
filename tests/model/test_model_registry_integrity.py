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
        assert artifact == peer, (
            f"{artifact['model_id']}: manifest and registry metadata differ"
        )


def test_dqn_entries_document_policy_metrics(manifest):
    """DQN agents are reinforcement-learning policies, not classifiers.

    test_f1/test_accuracy are intentionally null, and the held-out test-stage
    policy metrics must be recorded instead of leaving the entry undocumented.
    """
    dqn = [a for a in manifest["artifacts"] if a["model_type"] == "dqn"]
    assert dqn, "expected DQN policy artifacts in the registry"
    for artifact in dqn:
        assert artifact["test_f1"] is None, f"{artifact['model_id']}: test_f1 must stay null"
        assert artifact["test_accuracy"] is None, (
            f"{artifact['model_id']}: test_accuracy must stay null"
        )
        assert "not applicable" in artifact["metrics_note"]
        assert artifact["selection_metric"] == "mean_cost_per_flow"
        assert artifact["selected_step"] > 0
        assert artifact["test_mean_cost_per_flow"] > 0
        assert artifact["test_metrics_source"].endswith("final_test_metrics.json")


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
