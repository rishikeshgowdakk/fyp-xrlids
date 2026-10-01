"""Dataset manifest handling and integrity checks (build spec sections 5, 9, 39).

Rules enforced here:
* A checksum mismatch is a hard failure. Datasets are never silently replaced.
* A dataset that is not present locally is reported as ``DATA_NOT_AVAILABLE`` rather
  than being skipped quietly or replaced with generated rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from xrlids.utils.hashing import sha256_file
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

MANIFEST_PATH = "data/manifests/dataset_registry.yaml"


class DatasetIntegrityError(RuntimeError):
    """Raised on checksum mismatch or manifest inconsistency."""


class DatasetNotAvailableError(RuntimeError):
    """Raised when required dataset files are absent locally."""


@dataclass
class FileEntry:
    path: str
    sha256: str | None = None
    size_bytes: int | None = None

    @property
    def exists(self) -> bool:
        return Path(self.path).is_file()


def load_manifest(path: str | Path = MANIFEST_PATH) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not data or "datasets" not in data:
        raise DatasetIntegrityError(f"manifest '{path}' is missing a 'datasets' section")
    return data


def get_dataset_entry(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    for entry in manifest["datasets"]:
        if entry.get("key") == key:
            return entry
    raise KeyError(f"dataset '{key}' is not in the manifest")


def verify_files(entry: dict[str, Any], *, strict: bool = True) -> dict[str, Any]:
    """Verify every declared file's SHA256.

    Returns a report; raises on mismatch when ``strict``. Files with no recorded
    checksum are reported as ``unverifiable``, never as verified.
    """
    results: dict[str, Any] = {"dataset": entry.get("key"), "files": []}
    for f in entry.get("files") or []:
        item: dict[str, Any] = {"path": f.get("path"), "status": "unknown"}
        p = Path(f.get("path", ""))
        if not p.is_file():
            item["status"] = "missing"
            results["files"].append(item)
            continue
        expected = f.get("sha256")
        if not expected:
            item["status"] = "unverifiable"
            item["reason"] = "no sha256 recorded in the manifest"
        else:
            actual = sha256_file(p)
            item["actual_sha256"] = actual
            item["expected_sha256"] = expected
            item["status"] = "verified" if actual == expected else "mismatch"
            if actual != expected and strict:
                raise DatasetIntegrityError(
                    f"checksum mismatch for {p}: expected {expected[:12]}..., got {actual[:12]}..."
                )
        results["files"].append(item)

    statuses = {i["status"] for i in results["files"]}
    results["overall"] = (
        "no_files_declared" if not results["files"]
        else "missing" if "missing" in statuses
        else "mismatch" if "mismatch" in statuses
        else "unverifiable" if "unverifiable" in statuses
        else "verified"
    )
    return results


def dataset_availability(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    """Report whether a dataset is usable, without inventing anything if it is not."""
    entry = get_dataset_entry(manifest, key)
    files = entry.get("files") or []
    present = [f for f in files if Path(f.get("path", "")).is_file()]
    missing = [f for f in files if not Path(f.get("path", "")).is_file()]
    existing_file_names = [f.get("filename") or Path(f.get("path", "")).name for f in present]
    missing_file_names = [f.get("filename") or Path(f.get("path", "")).name for f in missing]
    availability = {
        "dataset": key,
        "declared_files": len(files),
        "present_files": len(present),
        "status": "DATA_NOT_AVAILABLE" if not present else "available",
        "existing_files": existing_file_names,
        "missing_files": missing_file_names,
    }
    if not present:
        availability["reason"] = (
            "no declared files found locally. Acquire the dataset and record SHA256 in "
            f"{MANIFEST_PATH} (see scripts/phase1/prepare_dataset.py)."
        )
    return availability


def verify_dataset_file(
    file_path: str | Path,
    dataset_key: str,
    manifest: dict[str, Any] | None = None,
    *,
    require_verified: bool = True,
) -> dict[str, Any]:
    """Verify that a specific dataset file exists, is in the manifest, and matches its SHA-256.

    Enforces the integrity gate before training:
    1. resolve the configured dataset file,
    2. verify that it is present on disk,
    3. verify that it is registered in the manifest,
    4. verify its SHA-256,
    5. refuse execution on mismatch,
    6. refuse execution if checksum verification is required but unavailable.
    """
    path = Path(file_path)
    if manifest is None:
        manifest = load_manifest()

    result: dict[str, Any] = {
        "dataset": dataset_key,
        "file": path.name,
        "path": str(path),
        "require_verified": require_verified,
        "exists": path.is_file(),
        "registered": False,
        "expected_sha256": None,
        "actual_sha256": None,
        "status": "unknown",
    }

    if not path.is_file():
        result["status"] = "missing_file"
        if require_verified:
            raise DatasetNotAvailableError(f"Dataset file '{path}' is not present on disk.")
        return result

    try:
        entry = get_dataset_entry(manifest, dataset_key)
    except KeyError:
        result["status"] = "unregistered_dataset"
        if require_verified:
            raise DatasetIntegrityError(f"Dataset '{dataset_key}' is not registered in the manifest.")
        return result

    files = entry.get("files") or []
    target_entry = None
    for f in files:
        f_name = f.get("filename") or Path(f.get("path", "")).name
        if f_name == path.name:
            target_entry = f
            break
        try:
            if Path(f.get("path", "")).resolve() == path.resolve():
                target_entry = f
                break
        except Exception:
            pass

    if target_entry is None:
        result["status"] = "unregistered_file"
        if require_verified:
            raise DatasetIntegrityError(
                f"File '{path.name}' is not registered in the manifest for dataset '{dataset_key}'."
            )
        return result

    result["registered"] = True
    expected_sha = target_entry.get("sha256")
    result["expected_sha256"] = expected_sha

    if not expected_sha:
        result["status"] = "unverifiable"
        if require_verified:
            raise DatasetIntegrityError(
                f"File '{path.name}' has no SHA-256 recorded in the manifest; verification required."
            )
        return result

    actual_sha = sha256_file(path)
    result["actual_sha256"] = actual_sha

    if actual_sha != expected_sha:
        result["status"] = "checksum_mismatch"
        if require_verified:
            raise DatasetIntegrityError(
                f"Checksum mismatch for '{path.name}': expected {expected_sha}, got {actual_sha}."
            )
        return result

    result["status"] = "verified"
    return result
