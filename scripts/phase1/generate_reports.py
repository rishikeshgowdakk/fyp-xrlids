#!/usr/bin/env python
"""Generate human-readable reports FROM machine-readable artifacts (build spec section 29).

Never hand-type a metric into Markdown: this script reads the registry, configs and result
JSON files and emits the tables, so documentation cannot drift from evidence.

    python scripts/phase1/generate_reports.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from xrlids.evaluation.metrics import metric_audit  # noqa: E402
from xrlids.evaluation.thresholding import DECISION_STATUS, OBJECTIVES  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.utils.env import environment_fingerprint, git_commit  # noqa: E402

OUT = Path("reports/generated")


def feature_compatibility(registry) -> str:
    lines = [
        "# Feature contract / dataset compatibility (generated)",
        "",
        f"Registry status: `{registry.status}` (frozen by `{registry.frozen_by_decision}`).",
        f"Column-map status: `{registry.column_maps_status}`.",
        "",
        "A feature is *supported* for a dataset when every semantic field it requires is",
        "declared in that dataset's column map. This is a **static** judgement about the",
        "contract; the audit must still confirm the raw column names exist in the files.",
        "",
        "| dataset | rung | supported | unsupported features |",
        "| --- | --- | --- | --- |",
    ]
    for dataset in registry.column_maps:
        for rung in registry.rungs:
            sup = registry.features_supported(dataset, rung)
            unsup = registry.unsupported_features(dataset, rung)
            total = len(registry.rung_features(rung))
            lines.append(
                f"| {dataset} | {rung} | {len(sup)}/{total} | {', '.join(unsup) if unsup else '-'} |"
            )
    lines += ["", "## Feature definitions", "", "| feature | formula | unit | live | directionality |", "| --- | --- | --- | --- | --- |"]
    from xrlids.features.definitions import FEATURES

    for name, spec in FEATURES.items():
        lines.append(
            f"| `{name}` | {spec.formula} | {spec.unit} | {'yes' if spec.live_available else 'no'} | {spec.directionality} |"
        )
    lines += ["", "## Decision-gate answers", "", "| feature | " + " | ".join(f"Q{i}" for i in range(1, 11)) + " |", "| --- | " + " | ".join(["---"] * 10) + " |"]
    keys = [
        "Q1_live", "Q2_cross_dataset", "Q3_identity_leak", "Q4_target_leak", "Q5_metadata",
        "Q6_unit", "Q7_improves", "Q8_hurts_cross", "Q9_cost", "Q10_justify",
    ]
    for name in FEATURES:
        gate = registry.gate_for(name)
        lines.append("| `" + name + "` | " + " | ".join(gate.get(k, "?") for k in keys) + " |")
    lines.append("")
    return "\n".join(lines)


def metrics_report() -> str:
    lines = [
        "# Metric implementation audit (generated)",
        "",
        "Every metric used in this project comes from one module (`src/xrlids/evaluation/metrics.py`).",
        "",
        "| metric | formula | implementation | input | edge cases |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in metric_audit():
        lines.append(
            f"| {row['metric']} | {row['formula']} | {row['implementation']} | {row['input']} | {row['edge_cases']} |"
        )
    lines.append("")
    return "\n".join(lines)


def status_report() -> str:
    env = environment_fingerprint()
    lines = [
        "# Phase 1 environment and status (generated)",
        "",
        f"Generated at commit: `{git_commit() or 'uncommitted'}`",
        "",
        "| item | value |",
        "| --- | --- |",
        f"| Python | {env['python_version']} |",
        f"| Platform | {env['platform']} |",
        f"| CUDA | {env['cuda_available']} |",
    ]
    for pkg, ver in sorted(env["packages"].items()):
        lines.append(f"| {pkg} | {ver} |")
    lines += [
        "",
        "## Threshold objective",
        "",
        f"Decision **D-003** is `{DECISION_STATUS}`.",
        "",
        "Candidate objectives implemented but NOT selected: " + ", ".join(f"`{o}`" for o in OBJECTIVES) + ".",
        "",
    ]
    return "\n".join(lines)


def results_report() -> str:
    """Summarise any smoke/test result artifacts that exist (clearly labelled)."""
    smoke = Path("results/smoke")
    lines = [
        "# Result artifacts (generated)",
        "",
        "Metrics below are read from result JSON. Fixture/smoke artifacts are marked and must",
        "not be cited as dataset results.",
        "",
    ]
    if not smoke.exists() or not list(smoke.glob("*.json")):
        lines += ["_No result artifacts found. Real dataset experiments require the datasets._", ""]
        return "\n".join(lines)

    for path in sorted(smoke.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        lines += [
            f"## {path.name}",
            "",
            f"- status: `{data.get('status')}`",
            f"- experiment: `{data.get('experiment_id')}`",
            f"- source: `{data.get('data_provenance', {}).get('source')}`",
        ]
        if data.get("smoke_test"):
            lines.append(f"- **{data['smoke_test']}**")
        metrics = data.get("test_metrics", {})
        if metrics:
            lines += ["", "| model | population | threshold | accuracy | precision | recall | f1 | roc_auc |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
            for model, m in metrics.items():
                lines.append(
                    f"| {model} | {m.get('population')} | {m.get('threshold')} | "
                    f"{m.get('accuracy')} | {m.get('precision')} | {m.get('recall')} | {m.get('f1')} | {m.get('roc_auc')} |"
                )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    registry = load_feature_registry()
    (OUT / "feature_compatibility.md").write_text(feature_compatibility(registry), encoding="utf-8")
    (OUT / "metric_audit.md").write_text(metrics_report(), encoding="utf-8")
    (OUT / "phase1_status.md").write_text(status_report(), encoding="utf-8")
    (OUT / "results_summary.md").write_text(results_report(), encoding="utf-8")
    print(f"wrote reports to {OUT}/")
    for p in sorted(OUT.glob("*.md")):
        print(f"  - {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
