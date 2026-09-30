#!/usr/bin/env python
"""Generate the feature-contract evidence artifact for decision D-002.

    python scripts/phase1/feature_contract_evidence.py

Combines:
  1. STATIC evidence from the registry: rung membership, decision-gate answers,
     per-dataset semantic availability, live computability.
  2. EMPIRICAL evidence when data exists: per-file schema validation of every declared
     column against the real file headers.
  3. MISSING evidence, stated explicitly (distribution behaviour, missingness, cost,
     validation-performance deltas) - these require the datasets and/or the feature
     sweep, and their absence is why D-002 stays OPEN.

Outputs:
  results/audits/feature_contract_evidence.json
  reports/generated/feature_contract_evidence.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import yaml  # noqa: E402

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact  # noqa: E402
from xrlids.datasets.prepare import dataset_status, load_manifest  # noqa: E402
from xrlids.datasets.schema import (  # noqa: E402
    SchemaValidationError,
    validate_dataset_schema,
)
from xrlids.features.definitions import FEATURES  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.utils.env import environment_fingerprint, git_commit  # noqa: E402

EVIDENCE_JSON = Path("results/audits/feature_contract_evidence.json")
EVIDENCE_MD = Path("reports/generated/feature_contract_evidence.md")


def _empirical_evidence(registry, contract, manifest) -> dict:
    """Per-dataset real-file schema validation. Datasets without files report honestly."""
    empirical: dict[str, dict] = {}
    for ds in manifest["datasets"]:
        key = ds["key"]
        status = dataset_status(key)
        if status["registered_files"] == 0 and status["files_present_but_unregistered"] == []:
            empirical[key] = {"status": "DATA_NOT_AVAILABLE", "reason": "no files registered or present"}
            continue
        raw_dir = Path("data/raw") / key
        try:
            spec = contract.datasets.get(key, {})
            report = validate_dataset_schema(
                raw_dir, key, registry, label_candidates=spec.get("label_column_candidates")
            )
            empirical[key] = {"status": "validated" if report.ok else "schema_conflict", **report.to_dict()}
        except (SchemaValidationError, FileNotFoundError) as exc:
            empirical[key] = {"status": "DATA_NOT_AVAILABLE", "reason": str(exc)}
    return empirical


def build_evidence() -> dict:
    registry = load_feature_registry()
    contract = load_label_contract()
    manifest = load_manifest()

    per_dataset: dict[str, dict] = {}
    for dataset in registry.column_maps:
        for rung in registry.rungs:
            sup = registry.features_supported(dataset, rung)
            unsup = registry.unsupported_features(dataset, rung)
            per_dataset.setdefault(dataset, {})[rung] = {
                "supported": sup,
                "unsupported": unsup,
                "n_supported": len(sup),
                "n_total": len(registry.rung_features(rung)),
            }

    live_blocked = {
        name: {"requires": list(spec.requires), "rationale": spec.limitations}
        for name, spec in FEATURES.items()
        if not spec.live_available
    }

    gate_unknown = {
        name: [q for q, a in registry.gate_for(name).items() if a in ("unverified", "partial")]
        for name in FEATURES
    }

    missing_evidence = {
        "distribution_behaviour": "requires real data audit (per-feature min/max/median, missingness, outliers)",
        "missingness": "requires real data audit",
        "quality_anomalies": "requires real data audit (constant columns, invalid values)",
        "validation_performance": "requires the feature sweep (blocked on D-004 acquisition)",
        "cross_dataset_performance": "requires the transfer experiments (blocked on D-005)",
        "computational_cost": "requires latency measurement with trained models",
    }

    return {
        "decision_id": "D-002",
        "decision_status": "OPEN - evidence provided, decision reserved to the project owner",
        "contract_status": registry.status,
        "rungs": {r: registry.rung_features(r) for r in registry.rungs},
        "rung_schema_hashes": {r: registry.schema_hash(r) for r in registry.rungs},
        "per_dataset_availability": per_dataset,
        "live_blocked_features": live_blocked,
        "gate_answers_with_gaps": {k: v for k, v in gate_unknown.items() if v},
        "empirical_schema_validation": _empirical_evidence(registry, contract, manifest),
        "missing_evidence_for_decision": missing_evidence,
        "options_available_to_owner": [
            "A. keep the candidate rungs as-is (R10 live-baseline intact; UNSW evaluated only at bespoke rungs)",
            "B. redefine rungs to a smallest-common cross-dataset contract (~4 features; weak in-domain)",
            "C. dual contracts: primary live-compatible + secondary per-dataset research contract",
            "D. per-dataset rungs with explicit non-comparability caveats in cross-dataset work",
        ],
        "recommendation_made": False,
        "note": (
            "This artifact is decision SUPPORT. The agent does not select an option; D-002 "
            "is resolved by the project owner with this evidence in hand."
        ),
        "metadata": ArtifactMetadata(
            experiment_id="EVIDENCE-D002-001",
            git_commit=git_commit(),
            extra={"environment": environment_fingerprint()},
        ).to_dict(),
    }


def render_markdown(evidence: dict) -> str:
    lines = [
        "# Feature-contract evidence (D-002 decision support)",
        "",
        f"Decision status: **{evidence['decision_status']}**",
        f"Contract status: `{evidence['contract_status']}`",
        "",
        "## Availability matrix",
        "",
        "| dataset | rung | supported | unsupported |",
        "| --- | --- | --- | --- |",
    ]
    for dataset, rungs in evidence["per_dataset_availability"].items():
        for rung, info in rungs.items():
            lines.append(
                f"| {dataset} | {rung} | {info['n_supported']}/{info['n_total']} | "
                f"{', '.join(info['unsupported']) if info['unsupported'] else '-'} |"
            )

    lines += ["", "## Live-computability", ""]
    if evidence["live_blocked_features"]:
        lines += ["| feature | blocked because |", "| --- | --- |"]
        for name, why in evidence["live_blocked_features"].items():
            lines.append(f"| `{name}` | {why['rationale'][:120]} |")
    else:
        lines.append("_All registry features are live-computable._")

    lines += ["", "## Empirical schema validation (real files)", ""]
    for dataset, emp in evidence["empirical_schema_validation"].items():
        lines.append(f"### {dataset}")
        if emp.get("status") == "DATA_NOT_AVAILABLE":
            lines += [f"- `{emp['status']}` - {emp.get('reason', '')}", ""]
            continue
        lines += [
            f"- status: `{emp['status']}`",
            f"- files checked: {emp['n_files']}",
            f"- identical schemas across files: {emp['files_identical_schema']}",
            f"- all declared columns present: {emp['all_declared_columns_present']}",
            "",
        ]

    lines += ["", "## Evidence still missing for the decision", ""]
    for k, v in evidence["missing_evidence_for_decision"].items():
        lines.append(f"- **{k}**: {v}")

    lines += ["", "## Options for the project owner", ""]
    for opt in evidence["options_available_to_owner"]:
        lines.append(f"- {opt}")
    lines += [
        "",
        "> No recommendation is made and no option is selected here. Resolving D-002 is a",
        "> project-owner decision; this artifact exists to make that decision evidence-based.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="generate D-002 feature-contract evidence")
    parser.add_argument("--out-json", default=str(EVIDENCE_JSON))
    parser.add_argument("--out-md", default=str(EVIDENCE_MD))
    args = parser.parse_args()

    evidence = build_evidence()
    write_json_artifact(
        args.out_json,
        {k: v for k, v in evidence.items() if k != "metadata"},
        ArtifactMetadata(
            experiment_id="EVIDENCE-D002-001",
            git_commit=evidence["metadata"]["git_commit"],
        ),
    )
    md_path = Path(args.out_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(evidence), encoding="utf-8")
    print(f"wrote {args.out_json}")
    print(f"wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
