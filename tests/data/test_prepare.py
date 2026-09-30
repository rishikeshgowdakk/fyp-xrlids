"""Tests for the reproducible dataset preparation workflow."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from xrlids.datasets.prepare import (
    PrepareError,
    acquisition_instructions,
    dataset_status,
    load_manifest,
    register_file,
    save_manifest,
    verify_dataset,
)


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    """A minimal manifest with one dataset, written to a temp dir."""
    manifest = {
        "registry_version": "test",
        "overall_acquisition_status": "not_acquired",
        "datasets": [
            {
                "key": "testds",
                "name": "Test Dataset",
                "source_url": "https://example.com/ds",
                "acquisition_status": "not_acquired",
                "acquisition_note": "test",
                "expected_files": [{"file": "a.csv"}, {"file": "b.csv"}],
                "files": [],
                "schema_status": "not_run",
                "label_status": "not_run",
                "audit_status": "not_run",
            }
        ],
    }
    path = tmp_path / "registry.yaml"
    save_manifest(manifest, path)
    return path


def _make_csv(directory: Path, name: str, content: str = "x,y\n1,2\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / name
    p.write_text(content)
    return p


def test_register_computes_real_checksum(tmp_path, manifest_path):
    f = _make_csv(tmp_path / "raw", "a.csv", "x,y\n1,2\n")
    record = register_file("testds", f, manifest_path=manifest_path)

    expected = hashlib.sha256(f.read_bytes()).hexdigest()
    assert record["sha256"] == expected
    assert record["status"] == "registered"
    assert record["size_bytes"] == f.stat().st_size

    manifest = load_manifest(manifest_path)
    assert manifest["datasets"][0]["files"][0]["sha256"] == expected


def test_register_missing_file_raises(tmp_path, manifest_path):
    with pytest.raises(PrepareError, match="does not exist"):
        register_file("testds", tmp_path / "nope.csv", manifest_path=manifest_path)


def test_register_all_expected_marks_available(tmp_path, manifest_path):
    raw = tmp_path / "raw"
    _make_csv(raw, "a.csv")
    _make_csv(raw, "b.csv")
    register_file("testds", raw / "a.csv", manifest_path=manifest_path)
    register_file("testds", raw / "b.csv", manifest_path=manifest_path)

    manifest = load_manifest(manifest_path)
    assert manifest["datasets"][0]["acquisition_status"] == "available"


def test_register_partial_marks_partial(tmp_path, manifest_path):
    raw = tmp_path / "raw"
    _make_csv(raw, "a.csv")
    register_file("testds", raw / "a.csv", manifest_path=manifest_path)

    manifest = load_manifest(manifest_path)
    assert manifest["datasets"][0]["acquisition_status"] == "partial"


def test_verify_passes_when_unchanged(tmp_path, manifest_path):
    f = _make_csv(tmp_path / "raw", "a.csv")
    register_file("testds", f, manifest_path=manifest_path)

    report = verify_dataset("testds", manifest_path=manifest_path)
    assert report["overall"] == "verified"
    assert report["files"][0]["status"] == "verified"


def test_verify_detects_mismatch_and_raises_strict(tmp_path, manifest_path):
    f = _make_csv(tmp_path / "raw", "a.csv", "original\n")
    register_file("testds", f, manifest_path=manifest_path)
    f.write_text("tampered\n")  # simulate silent data change

    with pytest.raises(PrepareError, match="mismatch"):
        verify_dataset("testds", manifest_path=manifest_path, strict=True)

    manifest = load_manifest(manifest_path)
    assert manifest["datasets"][0]["files"][0]["status"] == "mismatch"


def test_verify_detects_missing_file(tmp_path, manifest_path):
    f = _make_csv(tmp_path / "raw", "a.csv")
    register_file("testds", f, manifest_path=manifest_path)
    f.unlink()

    report = verify_dataset("testds", manifest_path=manifest_path, strict=False)
    assert report["overall"] == "missing"
    assert report["files"][0]["status"] == "missing"


def test_verify_empty_dataset_is_not_verified(tmp_path, manifest_path):
    report = verify_dataset("testds", manifest_path=manifest_path, strict=False)
    assert report["overall"] == "no_files_registered"


def test_status_reports_readiness(tmp_path, manifest_path):
    raw = tmp_path / "raw"
    _make_csv(raw, "a.csv")
    register_file("testds", raw / "a.csv", manifest_path=manifest_path)

    status = dataset_status("testds", manifest_path=manifest_path, raw_root=tmp_path / "raw" if False else str(tmp_path / "raw"))
    # layout in this fixture differs from the repo default; just check honest fields exist
    assert status["registered_files"] == 1
    assert status["ready_for_training"] is False  # schema not validated yet
    assert "schema_status" in status


def test_instructions_list_missing_files(tmp_path, manifest_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = acquisition_instructions(manifest_path=manifest_path)
    assert "a.csv" in text
    assert "b.csv" in text
    assert "register" in text


def test_manifest_backup_is_kept(tmp_path, manifest_path):
    f = _make_csv(tmp_path / "raw", "a.csv")
    register_file("testds", f, manifest_path=manifest_path)
    assert Path(str(manifest_path) + ".bak").exists()


def test_repo_manifest_is_parseable_and_honest():
    """The real manifest must declare provenance without inventing checksums."""
    manifest = load_manifest()
    for ds in manifest["datasets"]:
        assert ds["acquisition_status"] in {"not_acquired", "partial", "available", "verified", "failed"}
        for f in ds.get("files", []):
            # any registered file must have a plausible sha256 (64 hex chars)
            assert len(f["sha256"]) == 64
            assert all(c in "0123456789abcdef" for c in f["sha256"])
        # unacquired datasets must not carry files
        if ds["acquisition_status"] == "not_acquired":
            assert ds.get("files") in (None, [],)
