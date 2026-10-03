"""Integration test for Phase 2A baseline ladder execution and artifact generation."""

from pathlib import Path
import numpy as np
import pytest

from xrlids.response.costs import CostRegime
from xrlids.response.environment import FlowRecord
from xrlids.response.runner import run_phase2a_matrix
from xrlids.response.types import ActionSpaceMode


def test_phase2a_matrix_full_ladder():
    """Verify execution of the 4 baselines x 3 regimes x 2 modes (24 configurations)."""
    n_flows = 50
    flows = [
        FlowRecord(
            flow_id=f"flow_{i}",
            host_id=f"host_{i % 10}",
            attack_score=float(0.1 + 0.8 * (i % 2)),
            true_label=int(i % 2),
            flow_bytes_per_s=1000.0 * (i + 1),
        )
        for i in range(n_flows)
    ]

    results = run_phase2a_matrix(
        flows=flows,
        regimes=(
            CostRegime.STANDARD_ENTERPRISE,
            CostRegime.HIGH_AVAILABILITY,
            CostRegime.HIGH_SECURITY_ENCLAVE,
        ),
        action_modes=(
            ActionSpaceMode.FOUR_ACTION,
            ActionSpaceMode.THREE_ACTION,
        ),
        n_bootstraps=50,
        seed=42,
    )

    assert results["total_configurations"] == 24
    assert len(results["runs"]) == 24
    # 5 paired comparisons per regime (3 vs Baseline 0 + 2 vs Baseline 1) * 3 regimes * 2 modes = 30 comparisons
    assert results["total_comparisons"] == 30
    assert len(results["comparisons"]) == 30

    # Verify run metric structure
    for run in results["runs"]:
        assert "policy_name" in run
        assert "cost_regime" in run
        assert "action_mode" in run
        assert "total_cost" in run
        assert "false_quarantine_rate" in run
        assert "business_availability_score_pct" in run
        assert "action_chattering_index" in run
        assert "mitigation_delay_steps" in run
        assert run["total_flows"] == n_flows

    # Verify comparison structure
    for comp in results["comparisons"]:
        assert "baseline_name" in comp
        assert "candidate_name" in comp
        assert "mean_paired_difference" in comp
        assert "ci_lower" in comp
        assert "ci_upper" in comp
        assert "p_value" in comp
        assert "relative_cost_reduction_pct" in comp


def test_phase2a_artifact_integrity():
    """Verify committed Phase 2A baseline artifacts exist and are non-empty."""
    artifact_dir = Path("results/phase2/EXP-P2A-BASELINES-001")
    assert artifact_dir.is_dir()

    expected_files = [
        "experiment_config.json",
        "population_metadata.json",
        "baseline_metrics.json",
        "comparisons.json",
        "safety_override_summary.json",
        "phase2a_report.md",
    ]

    for fname in expected_files:
        fpath = artifact_dir / fname
        assert fpath.is_file(), f"Missing artifact: {fname}"
        assert fpath.stat().st_size > 0, f"Empty artifact: {fname}"


def test_phase2a_artifact_provenance_and_cooldown_reconciliation():
    """Verify artifact provenance contains 4adc69a, cooldown semantics are reconciled, and embedded config matches source YAML."""
    import json
    import yaml
    artifact_dir = Path("results/phase2/EXP-P2A-BASELINES-001")
    target_sha = "4adc69a853787c02ae67dd34ec3357667b4a0c7e"

    # Check JSON artifacts
    for jname in ["experiment_config.json", "population_metadata.json", "baseline_metrics.json", "comparisons.json", "safety_override_summary.json"]:
        data = json.loads((artifact_dir / jname).read_text(encoding="utf-8"))
        assert data["metadata"]["git_commit"] == target_sha, f"Mismatched git_commit in {jname}"

    # Check Markdown report
    report_text = (artifact_dir / "phase2a_report.md").read_text(encoding="utf-8")
    assert target_sha in report_text
    assert "30-step cooldown window (corresponding to T_cool = 30.0 s" in report_text or "W_{\\text{cooldown}} = 30$-step cooldown window" in report_text

    # Check embedded configuration matches source YAML safety-gate timing fields
    source_yaml_path = Path("configs/experiments/p2a_cicids2017_baselines.yaml")
    assert source_yaml_path.is_file(), "Source YAML config missing"
    with open(source_yaml_path, encoding="utf-8") as f:
        source_cfg = yaml.safe_load(f)

    exp_cfg = json.loads((artifact_dir / "experiment_config.json").read_text(encoding="utf-8"))
    embedded_sg = exp_cfg["config_yaml"]["safety_gate"]
    source_sg = source_cfg["safety_gate"]

    for timing_field in ["action_cooldown_steps", "step_duration_seconds", "cooldown_seconds"]:
        assert timing_field in source_sg, f"Missing {timing_field} in source YAML safety_gate"
        assert timing_field in embedded_sg, f"Missing {timing_field} in embedded config_yaml safety_gate"
        assert embedded_sg[timing_field] == source_sg[timing_field], (
            f"Divergence in {timing_field}: source YAML has {source_sg[timing_field]} but embedded config has {embedded_sg[timing_field]}"
        )
