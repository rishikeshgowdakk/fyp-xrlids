#!/usr/bin/env python
"""Run the real-data audit chain for every acquired dataset.

    python scripts/phase1/03_run_audit.py                # audit everything acquired
    python scripts/phase1/03_run_audit.py --dataset cicids2017

For each dataset with registered files this:
  1. validates every file's header against the declared column map (schema_status);
  2. audits each file (rows, NaN/Inf, duplicates, constants, duration anomalies,
     label distribution, unknown labels) and writes per-file + dataset-level artifacts;
  3. runs the label contract and records rejection accounting;
  4. updates the manifest statuses HONESTLY (validated only when validation passed).

Datasets without files are reported DATA_NOT_AVAILABLE and left untouched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pandas as pd  # noqa: E402

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact  # noqa: E402
from xrlids.datasets.audit import audit_file, summarize_audits  # noqa: E402
from xrlids.datasets.prepare import dataset_status, load_manifest, save_manifest  # noqa: E402
from xrlids.datasets.schema import SchemaValidationError, validate_dataset_schema  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.utils.env import environment_fingerprint, git_commit  # noqa: E402
from xrlids.utils.logging_utils import get_logger  # noqa: E402

logger = get_logger(__name__)

RESULTS = Path("results/audits")
REPORTS = Path("reports/generated/audits")


def audit_dataset(key: str, *, chunk_size: int | None = None) -> dict:
    registry = load_feature_registry()
    contract = load_label_contract()
    manifest = load_manifest()
    entry = next(d for d in manifest["datasets"] if d["key"] == key)
    spec = contract.datasets.get(key, {})

    status = dataset_status(key)
    paths = [Path(f["path"]) for f in entry.get("files", []) if Path(f["path"]).is_file()]
    if not paths:
        # fall back to unregistered files on disk (audit can still run, honestly labelled)
        raw_dir = Path("data/raw") / key
        paths = sorted(raw_dir.glob("*.csv")) if raw_dir.is_dir() else []
        if not paths:
            return {"dataset": key, "status": "DATA_NOT_AVAILABLE"}

    # ---- 1. schema validation --------------------------------------------------
    schema_block: dict = {"status": "not_run"}
    try:
        schema_report = validate_dataset_schema(
            Path("data/raw") / key, key, registry,
            label_candidates=spec.get("label_column_candidates"),
        )
        schema_block = {
            "status": "validated" if schema_report.ok else "schema_conflict",
            **schema_report.to_dict(),
        }
    except (SchemaValidationError, FileNotFoundError) as exc:
        schema_block = {"status": "failed", "reason": str(exc)}

    # ---- 2. per-file audit -------------------------------------------------------
    effective_chunk_size = chunk_size or 100_000
    audits = []
    for path in paths:
        logger.info("auditing %s", path)
        f_audit = audit_file(path, dataset=key, contract=contract, registry=registry, chunk_size=effective_chunk_size)
        audits.append(f_audit)
        file_artifact_path = RESULTS / key / f"{path.stem}_audit.json"
        file_artifact_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_artifact(
            file_artifact_path,
            f_audit,
            ArtifactMetadata(
                experiment_id=f"AUDIT-{key}-{path.stem}",
                dataset_sha256=f_audit.get("sha256"),
                extra={"environment": environment_fingerprint()},
            ),
        )
    summary = summarize_audits(audits)

    # ---- 3. label rejection accounting -------------------------------------------
    rejections = []
    for a in audits:
        rejections.extend(a.get("unknown_label_rejections", []))
    rejections_path = RESULTS / "label_rejections.csv"
    pd.DataFrame(rejections).to_csv(rejections_path, index=False) if rejections else None

    # ---- 4. artifacts --------------------------------------------------------------
    RESULTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "dataset": key,
        "schema_validation": schema_block,
        "per_file_audits": audits,
        "dataset_summary": summary,
        "unknown_label_rejections": rejections,
        "manifest_status_before": {
            "schema_status": entry.get("schema_status"),
            "label_status": entry.get("label_status"),
            "audit_status": entry.get("audit_status"),
        },
    }
    write_json_artifact(
        RESULTS / f"{key}_audit.json",
        payload,
        ArtifactMetadata(
            experiment_id=f"AUDIT-{key}-001",
            dataset_sha256=(entry.get("files") or [{}])[0].get("sha256"),
            extra={"environment": environment_fingerprint()},
        ),
    )

    REPORTS.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Dataset audit - {key} (generated)",
        "",
        f"Files audited: {len(audits)} · Rows total: {summary['total_rows']} · "
        f"Duplicate rows: {summary['total_duplicate_rows']}",
        f"Schema validation: `{schema_block['status']}`",
        "",
        "## Per-file",
        "",
        "| file | rows | columns | duplicates | NaN | Inf |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for a in audits:
        lines.append(
            f"| {Path(a['source_file']).name} | {a['rows']} | {a['columns']} | "
            f"{a['duplicate_rows']} | {a.get('total_nan', '-')} | {a.get('total_inf', '-')} |"
        )
    lines += ["", "## Label audit (first file)", "", "```json",
              json.dumps(audits[0].get("label_audit", {}), indent=2, default=str), "```", ""]
    if rejections:
        lines += ["## Unknown-label rejections", "", "```json",
                  json.dumps(rejections, indent=2, default=str), "```", ""]
    (REPORTS / f"{key}_audit.md").write_text("\n".join(lines), encoding="utf-8")

    # ---- 5. honest manifest status update -----------------------------------------
    entry["schema_status"] = "validated" if schema_block["status"] == "validated" else "failed"
    entry["audit_status"] = "completed"
    label_ok = all(a.get("label_audit", {}).get("rows_rejected_unknown_label", 0) == 0 for a in audits)
    entry["label_status"] = "validated" if label_ok else "rejected_labels_present"
    save_manifest(manifest)

    logger.info("dataset %s audited: %d files, %d rows", key, len(audits), summary["total_rows"])
    return {
        "dataset": key,
        "status": "completed",
        "files": len(audits),
        "rows": summary["total_rows"],
        "schema_status": schema_block["status"],
        "label_status": entry["label_status"],
        "artifacts": [str(RESULTS / f"{key}_audit.json"), str(REPORTS / f"{key}_audit.md")],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="audit acquired datasets")
    parser.add_argument("--dataset", default=None, help="audit one dataset (default: all)")
    parser.add_argument("--chunk-size", type=int, default=100_000, help="stream large CSVs in chunks of N rows (default: 100000)")
    args = parser.parse_args()

    manifest = load_manifest()
    keys = [args.dataset] if args.dataset else [d["key"] for d in manifest["datasets"]]

    out = [audit_dataset(k, chunk_size=args.chunk_size) for k in keys]

    summary_path = RESULTS / "dataset_summary.json"
    RESULTS.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))
    print(f"\nsummary: {summary_path}")
    if any(o["status"] == "DATA_NOT_AVAILABLE" for o in out):
        print(
            "\nSome datasets are not acquired. Place files per:\n"
            "  python scripts/phase1/prepare_dataset.py instructions",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
