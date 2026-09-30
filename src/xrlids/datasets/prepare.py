"""Reproducible dataset preparation (build spec sections 5-7, 25, 27).

This module is the ONLY sanctioned way to enter checksums into the manifest:

    register  - compute size + SHA256 from an actually-present file and record it
    verify    - recompute checksums of registered files and compare
    status    - report what is present/missing/verified without fabricating anything

Design rules:
* A sha256 value can never be hand-authored: it is computed from the bytes on disk.
* A file absent from disk is reported missing; it is never "verified" by optimism.
* The manifest is updated atomically and a backup of the previous version is kept.
* No downloading happens here. Acquisition constraints (mirrors unreachable) are
  recorded in the manifest, and clear instructions are produced instead.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from xrlids.utils.hashing import sha256_file
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

MANIFEST_PATH = Path("data/manifests/dataset_registry.yaml")


class PrepareError(RuntimeError):
    """Raised when a preparation operation cannot be completed honestly."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_manifest(path: str | Path = MANIFEST_PATH) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def save_manifest(manifest: dict[str, Any], path: str | Path = MANIFEST_PATH) -> Path:
    """Atomically persist the manifest, keeping one backup of the previous version."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8")
    tmp.replace(path)
    return path


def get_entry(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    for entry in manifest.get("datasets", []):
        if entry.get("key") == key:
            return entry
    raise KeyError(f"dataset '{key}' is not declared in the manifest")


def _update_overall_status(manifest: dict[str, Any]) -> None:
    statuses = [d.get("acquisition_status", "not_acquired") for d in manifest.get("datasets", [])]
    if all(s == "verified" for s in statuses):
        manifest["overall_acquisition_status"] = "verified"
    elif any(s in ("available", "verified") for s in statuses):
        manifest["overall_acquisition_status"] = "partial"
    elif any(s == "failed" for s in statuses):
        manifest["overall_acquisition_status"] = "failed"
    else:
        manifest["overall_acquisition_status"] = "not_acquired"


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------
def register_file(
    dataset_key: str,
    file_path: str | Path,
    *,
    manifest_path: str | Path = MANIFEST_PATH,
    source: str | None = None,
) -> dict[str, Any]:
    """Compute SHA256/size from a real file and record it in the manifest.

    The file must exist; this function never fabricates a checksum. If the same file
    (by absolute path) was already registered, it is re-registered (updated), because
    re-hashing an existing file is harmless and self-correcting.
    """
    file_path = Path(file_path).resolve()
    if not file_path.is_file():
        raise PrepareError(f"cannot register '{file_path}': file does not exist")

    manifest = load_manifest(manifest_path)
    entry = get_entry(manifest, dataset_key)

    digest = sha256_file(file_path)
    record = {
        "path": str(file_path),
        "filename": file_path.name,
        "size_bytes": file_path.stat().st_size,
        "sha256": digest,
        "status": "registered",
        "source": source or "manual download (see acquisition_note)",
        "registered_at": _now(),
    }

    files = [f for f in entry.get("files", []) if f.get("path") != str(file_path)]
    files.append(record)
    entry["files"] = files

    expected = {e["file"] for e in entry.get("expected_files", [])}
    registered_names = {Path(f["path"]).name for f in files}
    if expected and expected <= registered_names:
        entry["acquisition_status"] = "available"   # every expected file registered
    else:
        entry["acquisition_status"] = "partial"      # something registered, but not the full expected set
    _update_overall_status(manifest)
    save_manifest(manifest, manifest_path)

    logger.info(
        "registered dataset=%s file=%s sha256=%s size=%d",
        dataset_key, file_path.name, digest[:16], record["size_bytes"],
    )
    return record


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def verify_dataset(
    dataset_key: str,
    *,
    manifest_path: str | Path = MANIFEST_PATH,
    strict: bool = True,
) -> dict[str, Any]:
    """Recompute checksums of every registered file for one dataset.

    A file that vanished after registration becomes 'missing' (never silently
    'verified'). A changed checksum becomes 'mismatch' and raises in strict mode.
    """
    manifest = load_manifest(manifest_path)
    entry = get_entry(manifest, dataset_key)

    results = []
    for f in entry.get("files", []):
        path = Path(f["path"])
        item: dict[str, Any] = {"path": f["path"], "filename": f.get("filename")}
        if not path.is_file():
            item["status"] = "missing"
            item["reason"] = "registered file is no longer present on disk"
        else:
            actual = sha256_file(path)
            item["actual_sha256"] = actual
            item["expected_sha256"] = f.get("sha256")
            item["status"] = "verified" if actual == f.get("sha256") else "mismatch"
        results.append(item)
        f["status"] = item["status"]
        if item["status"] == "mismatch":
            f["mismatch_detected_at"] = _now()

    statuses = {r["status"] for r in results}
    overall = (
        "no_files_registered" if not results
        else "mismatch" if "mismatch" in statuses
        else "missing" if "missing" in statuses
        else "verified"
    )
    if overall == "verified":
        entry["acquisition_status"] = "verified"
    elif overall in ("mismatch", "missing"):
        entry["acquisition_status"] = "failed" if overall == "mismatch" else entry.get("acquisition_status", "partial")
    _update_overall_status(manifest)
    save_manifest(manifest, manifest_path)

    report = {"dataset": dataset_key, "overall": overall, "files": results}
    if strict and overall == "mismatch":
        raise PrepareError(
            f"checksum mismatch for dataset '{dataset_key}': the data on disk differs from "
            "what was registered. Investigate before proceeding - do not re-register to "
            "silence this."
        )
    return report


# ---------------------------------------------------------------------------
# status / instructions
# ---------------------------------------------------------------------------
def dataset_status(
    dataset_key: str,
    *,
    manifest_path: str | Path = MANIFEST_PATH,
    raw_root: str | Path = "data/raw",
) -> dict[str, Any]:
    """Where does this dataset stand? Expected vs registered vs verified."""
    manifest = load_manifest(manifest_path)
    entry = get_entry(manifest, dataset_key)

    expected = [e["file"] for e in entry.get("expected_files", [])]
    expected_dir = Path(raw_root) / dataset_key
    on_disk_expected = sorted(p.name for p in expected_dir.glob("*.csv")) if expected_dir.is_dir() else []

    registered = entry.get("files", [])
    verified = [f for f in registered if f.get("status") == "verified"]

    unregistered_on_disk = sorted(set(on_disk_expected) - {Path(f["path"]).name for f in registered})

    return {
        "dataset": dataset_key,
        "acquisition_status": entry.get("acquisition_status", "not_acquired"),
        "source_url": entry.get("source_url"),
        "expected_files": len(expected),
        "registered_files": len(registered),
        "verified_files": len(verified),
        "files_present_but_unregistered": unregistered_on_disk,
        "schema_status": entry.get("schema_status", "not_run"),
        "label_status": entry.get("label_status", "not_run"),
        "audit_status": entry.get("audit_status", "not_run"),
        "ready_for_audit": bool(registered or on_disk_expected),
        "ready_for_training": bool(verified) and entry.get("schema_status") == "validated",
    }


def acquisition_instructions(
    *,
    manifest_path: str | Path = MANIFEST_PATH,
) -> str:
    """Exact, honest instructions for obtaining each dataset."""
    manifest = load_manifest(manifest_path)
    lines = ["# Dataset acquisition instructions", ""]

    for entry in manifest.get("datasets", []):
        key = entry.get("key")
        lines += [
            f"## {entry.get('name')} (`{key}`)",
            "",
            f"- Status: `{entry.get('acquisition_status')}`",
            f"- Official source: {entry.get('source_url')}",
            f"- Place files in: `{entry.get('acquisition_note', '').strip()}`" if False else f"- Place files in: `data/raw/{key}/`",
        ]
        note = (entry.get("acquisition_note") or "").strip()
        if note:
            lines += ["", note]
        missing = [
            e["file"]
            for e in entry.get("expected_files", [])
            if Path(f"data/raw/{key}") / e["file"] and not (Path(f"data/raw/{key}") / e["file"]).is_file()
        ]
        if missing:
            lines += ["", "Expected but not present:", ""]
            lines += [f"- `{m}`" for m in missing]
        lines.append("")

    lines += [
        "After placing files:",
        "",
        "```bash",
        "# 1. register every CSV you downloaded (computes SHA256 from the actual bytes)",
        "python scripts/phase1/prepare_dataset.py register --dataset <key> --all",
        "",
        "# 2. verify checksums (re-reads files and compares)",
        "python scripts/phase1/prepare_dataset.py verify --dataset <key>",
        "",
        "# 3. audit each file",
        "python scripts/phase1/01_dataset_audit.py --dataset <key> --input <file.csv>",
        "```",
        "",
        "Nothing in this workflow fabricates state: a file that was never downloaded stays",
        "`expected`; a file whose checksum changes becomes `mismatch` and stops the pipeline.",
    ]
    return "\n".join(lines)
