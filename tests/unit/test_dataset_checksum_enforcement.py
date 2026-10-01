"""Tests for dataset checksum enforcement (Task 4, BS-011, BS-017).

Before any real experiment runs:
1. resolve the configured dataset file,
2. verify that it is present,
3. verify that it is registered in the manifest,
4. verify its SHA-256,
5. refuse execution on mismatch,
6. refuse execution if checksum verification is required but unavailable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from xrlids.datasets.loading import (
    DatasetIntegrityError,
    DatasetNotAvailableError,
    load_manifest,
    verify_dataset_file,
)


@pytest.fixture
def temp_manifest(tmp_path: Path) -> Path:
    raw_dir = tmp_path / "data" / "raw" / "mock_ds"
    raw_dir.mkdir(parents=True, exist_ok=True)
    test_file = raw_dir / "traffic.csv"
    content = b"Flow Duration,Total Fwd Packets,Label\n100,2,BENIGN\n"
    test_file.write_bytes(content)
    file_sha = hashlib.sha256(content).hexdigest()

    manifest_data = {
        "registry_version": "test",
        "datasets": [
            {
                "key": "mock_ds",
                "name": "Mock Dataset",
                "files": [
                    {
                        "path": str(test_file),
                        "filename": "traffic.csv",
                        "size_bytes": len(content),
                        "sha256": file_sha,
                        "status": "verified",
                    },
                    {
                        "path": str(raw_dir / "unverifiable.csv"),
                        "filename": "unverifiable.csv",
                        "size_bytes": 100,
                        "sha256": "",  # missing checksum
                        "status": "registered",
                    },
                ],
            }
        ],
    }
    manifest_path = tmp_path / "dataset_registry.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest_data), encoding="utf-8")
    return manifest_path


def test_verify_dataset_file_valid_checksum(temp_manifest):
    manifest = load_manifest(temp_manifest)
    file_path = Path(manifest["datasets"][0]["files"][0]["path"])
    res = verify_dataset_file(file_path, "mock_ds", manifest, require_verified=True)
    assert res["status"] == "verified"
    assert res["actual_sha256"] == res["expected_sha256"]
    assert res["registered"] is True


def test_verify_dataset_file_checksum_mismatch_raises(temp_manifest):
    manifest = load_manifest(temp_manifest)
    file_path = Path(manifest["datasets"][0]["files"][0]["path"])
    # Corrupt the file contents
    file_path.write_bytes(b"tampered content\n")

    with pytest.raises(DatasetIntegrityError, match="Checksum mismatch"):
        verify_dataset_file(file_path, "mock_ds", manifest, require_verified=True)


def test_verify_dataset_file_checksum_mismatch_when_not_required(temp_manifest):
    manifest = load_manifest(temp_manifest)
    file_path = Path(manifest["datasets"][0]["files"][0]["path"])
    file_path.write_bytes(b"tampered content\n")

    res = verify_dataset_file(file_path, "mock_ds", manifest, require_verified=False)
    assert res["status"] == "checksum_mismatch"
    assert res["actual_sha256"] != res["expected_sha256"]


def test_verify_dataset_file_missing_file_raises(temp_manifest):
    manifest = load_manifest(temp_manifest)
    missing_path = Path(temp_manifest.parent / "nonexistent.csv")

    with pytest.raises(DatasetNotAvailableError, match="not present on disk"):
        verify_dataset_file(missing_path, "mock_ds", manifest, require_verified=True)

    res = verify_dataset_file(missing_path, "mock_ds", manifest, require_verified=False)
    assert res["status"] == "missing_file"


def test_verify_dataset_file_unregistered_file_raises(temp_manifest):
    manifest = load_manifest(temp_manifest)
    raw_dir = Path(manifest["datasets"][0]["files"][0]["path"]).parent
    unregistered = raw_dir / "unregistered.csv"
    unregistered.write_bytes(b"some,data\n1,2\n")

    with pytest.raises(DatasetIntegrityError, match="not registered in the manifest"):
        verify_dataset_file(unregistered, "mock_ds", manifest, require_verified=True)

    res = verify_dataset_file(unregistered, "mock_ds", manifest, require_verified=False)
    assert res["status"] == "unregistered_file"


def test_verify_dataset_file_missing_manifest_dataset_raises(temp_manifest):
    manifest = load_manifest(temp_manifest)
    file_path = Path(manifest["datasets"][0]["files"][0]["path"])

    with pytest.raises(DatasetIntegrityError, match="not registered in the manifest"):
        verify_dataset_file(file_path, "unknown_dataset_key", manifest, require_verified=True)


def test_verify_dataset_file_unverifiable_sha_raises(temp_manifest):
    manifest = load_manifest(temp_manifest)
    raw_dir = Path(manifest["datasets"][0]["files"][0]["path"]).parent
    unverifiable_file = raw_dir / "unverifiable.csv"
    unverifiable_file.write_bytes(b"data\n")

    with pytest.raises(DatasetIntegrityError, match="no SHA-256 recorded"):
        verify_dataset_file(unverifiable_file, "mock_ds", manifest, require_verified=True)

    res = verify_dataset_file(unverifiable_file, "mock_ds", manifest, require_verified=False)
    assert res["status"] == "unverifiable"
