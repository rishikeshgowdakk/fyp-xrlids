"""Comprehensive regression and scientific consistency audit test suite for Phase 2.

Verifies:
1. RQ7 Comparator Selection: Identifies lowest-cost deterministic baseline (Baseline 2: Two-Tier).
2. DQN Training Configuration Integrity: Verifies training parameters match committed artifact.
3. Phase 2C State Ablation Consistency: Verifies empirical cost ordering matches state_ablation_results.json.
4. Phase 2D Jitter Robustness Evaluation: Verifies ACI > 0.05 is accurately classified as FAIL.
5. Critical-Host Safety Gate and Audit Integrity: Verifies critical infrastructure cannot be isolated and audit cards reflect override.
6. 6D State Dimension Contract: Verifies StateBuilder produces [S_t, Delta S_t, N_alert, a_(t-1), c_t, v_t].
7. No Label In State: Verifies zero ground truth labels in observation vector.
8. No Future Information: Verifies state is computed strictly on historical window.
9. Simulator Causal Transition Semantics: Verifies policy dynamics vs exogenous flow replay.
"""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pytest

from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.environment import FlowRecord, OfflineResponseSimulator
from xrlids.response.explainability.audit_card import explain_state_factors
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode


def test_rq7_comparator_identifies_best_deterministic_baseline():
    """Verify that RQ7 comparison logic evaluates against the lowest-cost deterministic baseline."""
    bootstrap_file = Path("results/phase2/EXP-P2-FINAL-TEST-001/final_test_bootstrap.json")
    assert bootstrap_file.exists(), "Final test bootstrap artifact must exist"

    with open(bootstrap_file) as f:
        data = json.load(f)

    comps = data["bootstrap_comparisons"]
    std_comps = [c for c in comps if c["cost_regime"] == "standard_enterprise"]

    # 3-action mode
    b_3 = [c for c in std_comps if c.get("action_mode") == "3-action"]
    # 4-action mode
    b_4 = [c for c in std_comps if c.get("action_mode") == "4-action"]

    # In both action modes, Baseline 2 is the best (lowest cost / lowest delta) deterministic comparator
    b2_3 = next(c for c in b_3 if "Baseline_2" in c["baseline_name"])
    b2_4 = next(c for c in b_4 if "Baseline_2" in c["baseline_name"])
    b1_3 = next(c for c in b_3 if "Baseline_1" in c["baseline_name"])
    b1_4 = next(c for c in b_4 if "Baseline_1" in c["baseline_name"])

    # Relative cost reduction vs Baseline 2 is less than vs Baseline 1
    assert b2_3["relative_cost_reduction_pct"] < b1_3["relative_cost_reduction_pct"]
    assert b2_4["relative_cost_reduction_pct"] < b1_4["relative_cost_reduction_pct"]

    # Effect sizes vs Baseline 2 fall below the 15.0% pre-registered threshold
    assert b2_3["relative_cost_reduction_pct"] < 15.0, "3-action vs Baseline 2 must be < 15%"
    assert b2_4["relative_cost_reduction_pct"] < 15.0, "4-action vs Baseline 2 must be < 15%"

    # However, improvements are statistically significant
    assert b2_3["p_value"] < 0.01
    assert b2_4["p_value"] < 0.01


def test_dqn_training_configuration_matches_artifact():
    """Verify DQN training configuration matches the authoritative machine-generated artifact."""
    cfg_file = Path("results/phase2/EXP-P2B-DQN-001/training_config.json")
    assert cfg_file.exists(), "DQN training config artifact must exist"

    with open(cfg_file) as f:
        cfg = json.load(f)

    for mode_key in ("three_action", "four_action"):
        mode_cfg = cfg[mode_key]
        assert mode_cfg["learning_rate"] == 0.001
        assert mode_cfg["gamma"] == 0.95
        assert mode_cfg["epsilon_decay_steps"] == 50000
        assert mode_cfg["replay_capacity"] == 100000
        assert mode_cfg["per_alpha"] == 0.6
        assert mode_cfg["beta_start"] == 0.4
        assert mode_cfg["beta_end"] == 1.0
        assert mode_cfg["tau_target"] == 0.005
        assert mode_cfg["total_steps"] == 50000


def test_phase2c_state_ablation_artifact_consistency():
    """Verify Phase 2C state ablation values match state_ablation_results.json."""
    ablation_file = Path("results/phase2/EXP-P2C-SENSITIVITY-001/state_ablation_results.json")
    assert ablation_file.exists(), "State ablation artifact must exist"

    with open(ablation_file) as f:
        data = json.load(f)

    ablations_dict = {a["condition_id"]: a for a in data["ablations"]}

    # Full state cost
    assert ablations_dict["full_state"]["total_cost"] == 348930.0

    # Volumetric context ablation has lower cost than full state
    assert ablations_dict["ablate_volumetric_context"]["total_cost"] < ablations_dict["full_state"]["total_cost"]

    # Cooldown ablation has identical cost to full state in this replay setting
    assert ablations_dict["ablate_cooldown_state"]["total_cost"] == ablations_dict["full_state"]["total_cost"]

    # Previous action ablation produces largest degradation
    costs = {k: v["total_cost"] for k, v in ablations_dict.items()}
    assert max(costs, key=costs.get) == "ablate_previous_action"


def test_phase2d_jitter_evaluation_detects_fail():
    """Verify that score jitter robustness evaluation detects ACI > 0.05 as FAIL."""
    jitter_file = Path("results/phase2/EXP-P2D-ROBUSTNESS-001/score_jitter_robustness.json")
    assert jitter_file.exists(), "Score jitter artifact must exist"

    with open(jitter_file) as f:
        jitter_data = json.load(f)

    for entry in jitter_data["jitter_sweeps"]:
        aci = entry["action_chattering_index"]
        # All evaluated jitter levels have ACI > 0.05, failing pre-registered stability bound
        assert aci > 0.05, f"Expected ACI > 0.05, got {aci} at sigma={entry['sigma']}"


def test_state_builder_dimension_and_range_contract():
    """Verify StateBuilder strictly adheres to 6D state contract [S_t, Delta S_t, N_alert, a_(t-1), c_t, v_t]."""
    sb = StateBuilder(score_trajectory_k=5, alert_density_window_w=20)
    sb.reset()

    # Step 1: initial state
    s1 = sb.build_state(attack_score=0.85, flow_bytes_per_s=1000.0)
    assert len(s1) == 6
    assert isinstance(s1, np.ndarray)
    assert s1.shape == (6,)

    # Dimension 0: threat score
    assert s1[0] == pytest.approx(0.85, rel=1e-5)
    # Dimension 1: trajectory
    assert -1.0 <= s1[1] <= 1.0
    # Dimension 2: alert density
    assert 0.0 <= s1[2] <= 1.0
    # Dimension 3: previous action (initially 0.0)
    assert s1[3] == 0.0
    # Dimension 4: cooldown fraction
    assert 0.0 <= s1[4] <= 1.0
    # Dimension 5: volume scale
    assert 0.0 <= s1[5] <= 1.0

    # Step 2: update history and check dimension 3 & 4
    sb.update_history(attack_score=0.85, enforced_action=Action.ISOLATE, cooldown_remaining=25)
    s2 = sb.build_state(attack_score=0.90, flow_bytes_per_s=50000.0)
    assert s2[3] == pytest.approx(1.0, rel=1e-5)  # ISOLATE = 1.0
    assert s2[4] == pytest.approx(25.0 / 30.0, rel=1e-5)  # 25 remaining / 30


def test_no_labels_or_future_information_in_state():
    """Verify that StateBuilder does not consume or contain labels or future information."""
    sb = StateBuilder()
    sb.reset()

    import inspect
    sig = inspect.signature(sb.build_state)
    param_names = list(sig.parameters.keys())
    assert "label" not in param_names
    assert "true_label" not in param_names
    assert "y" not in param_names
    assert "ground_truth" not in param_names
    assert "future_flows" not in param_names


def test_critical_host_safety_and_audit_consistency():
    """Verify critical infrastructure cannot be isolated and audit explanation matches."""
    critical_hosts = frozenset(["host_gateway", "host_dns", "host_0", "host_1"])
    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION, critical_hosts=critical_hosts)

    for h in critical_hosts:
        enforced, overridden, reason = gate.enforce_safety(
            step=1, flow_id=1, host_id=h, proposed_action=Action.ISOLATE
        )
        assert enforced == Action.ALERT
        assert overridden is True
        assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"

        # Check explain_state_factors does NOT emit contradictory factor
        dummy_state = np.array([0.95, 0.20, 0.80, 0.0, 0.0, 0.5])
        factors = explain_state_factors(dummy_state, enforced_action="ALERT", is_critical=True)
        assert any("critical infrastructure" in f for f in factors)
        assert not any("standard network inventory" in f for f in factors)

    # Standard host
    enforced, overridden, reason = gate.enforce_safety(
        step=2, flow_id=2, host_id="host_standard_99", proposed_action=Action.ISOLATE
    )
    assert enforced == Action.ISOLATE
    assert overridden is False
    dummy_state = np.array([0.95, 0.20, 0.80, 0.0, 0.0, 0.5])
    factors = explain_state_factors(dummy_state, enforced_action="ISOLATE", is_critical=False)
    assert any("standard network inventory" in f for f in factors)
    assert not any("critical infrastructure" in f for f in factors)


def test_simulator_causal_transition_semantics():
    """Verify simulator causal state transition: action affects policy dynamics, flows are exogenous."""
    cost_engine = ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE)
    safety_gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    state_builder = StateBuilder()

    flows = [
        FlowRecord(flow_id=1, host_id="host_10", attack_score=0.90, true_label=1, flow_bytes_per_s=500.0),
        FlowRecord(flow_id=2, host_id="host_10", attack_score=0.85, true_label=1, flow_bytes_per_s=500.0),
    ]

    sim = OfflineResponseSimulator(
        flows=flows,
        cost_engine=cost_engine,
        safety_gate=safety_gate,
        state_builder=state_builder,
        action_mode=ActionSpaceMode.FOUR_ACTION,
    )

    # Step 1: initial state
    s0 = sim.reset()
    assert s0[3] == 0.0  # initial action ALLOW
    assert s0[4] == 0.0  # initial cooldown 0.0

    # Take ISOLATE action
    s1, reward, done, info = sim.step(Action.ISOLATE)

    # Action causally updated policy-observable state:
    assert s1[3] == 1.0  # previous action now ISOLATE (1.0)
    assert s1[4] > 0.0  # cooldown fraction now active (> 0.0)

    # But incoming flow 2 features remain exogenous:
    assert sim.flows[1].attack_score == 0.85
    assert sim.flows[1].true_label == 1


def test_hypothesis_definitions_and_effect_size_distinction():
    """Verify H0/H1 are defined around statistical significance and 15% effect-size is separated."""
    spec_path = Path("docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md")
    report_path = Path("docs/phase2/PHASE2_FINAL_REPORT.md")
    assert spec_path.exists() and report_path.exists()

    spec_text = spec_path.read_text(encoding="utf-8")
    report_text = report_path.read_text(encoding="utf-8")

    # Authoritative H0: does not achieve a statistically significant reduction
    assert "does not achieve a statistically significant reduction in cumulative operational cost" in spec_text
    assert "does NOT achieve a statistically significant reduction in cumulative operational cost" in report_text

    # Authoritative H1: achieves lower cumulative cost
    assert "achieves lower cumulative cost" in spec_text
    assert "achieves lower cumulative cost" in report_text

    # Final report separates statistical significance from 15% practical effect-size target
    assert "$H_0$ is REJECTED" in report_text or "$H_0$ Rejected" in report_text
    assert "$H_1$ is SUPPORTED" in report_text or "$H_1$ Supported" in report_text
    assert "practical effect-size criterion" in report_text or "Practical Effect-Size Criterion" in report_text
    assert "NOT MET" in report_text

    # Verify PHASE2_FINAL_REPORT.md does not contain contradictory 'H0 Upheld' for RQ7
    assert "H0 Upheld" not in report_text
    assert "H₀ Upheld" not in report_text
    assert "$H_0$ Upheld" not in report_text
    assert "$H_0$ is upheld" not in report_text
    assert "H_0 is upheld" not in report_text


def test_phase2e_count_consistency_across_all_documents():
    """Verify Phase 2E intervention and card count is exactly 28,167 across all documents."""
    final_report = Path("docs/phase2/PHASE2_FINAL_REPORT.md").read_text(encoding="utf-8")
    phase2e_report = Path("results/phase2/EXP-P2E-EXPLAINABILITY-001/phase2e_report.md").read_text(encoding="utf-8")
    claims_registry = Path("docs/03_DECISIONS/CLAIMS_REGISTRY.md").read_text(encoding="utf-8")

    with open("results/phase2/EXP-P2E-EXPLAINABILITY-001/safety_audit_metrics.json") as f:
        metrics_json = json.load(f)

    # 1. safety_audit_metrics.json
    assert metrics_json["audit_metrics"]["non_allow_interventions_count"] == 28167
    assert metrics_json["audit_metrics"]["audit_cards_generated"] == 28167

    # 2. PHASE2_FINAL_REPORT.md
    assert "28,167" in final_report
    assert "28,168" not in final_report

    # 3. phase2e_report.md
    assert "28,167" in phase2e_report
    assert "28,168" not in phase2e_report

    # 4. CLAIMS_REGISTRY.md (specifically CLAIM-028)
    assert "28,167" in claims_registry
    assert "28,168" not in claims_registry


def test_stealth_campaign_empirical_action_counts():
    """Verify stealth campaign action counts match stealth_campaign_results.json."""
    stealth_file = Path("results/phase2/EXP-P2D-ROBUSTNESS-001/stealth_campaign_results.json")
    assert stealth_file.exists()

    with open(stealth_file) as f:
        data = json.load(f)

    families = {fam["family_name"]: fam for fam in data["families"]}

    # Infiltration (20 flows)
    infil = families["INFILTRATION"]
    assert infil["sample_count"] == 20
    assert infil["action_counts"] == {"ALLOW": 18, "ALERT": 2, "RATE_LIMIT": 0, "ISOLATE": 0}
    assert infil["mitigation_delay_steps"] == 50.0

    # Web Attack - Brute Force (100 flows)
    bf = families["WEB ATTACK - BRUTE FORCE"]
    assert bf["sample_count"] == 100
    assert bf["action_counts"] == {"ALLOW": 70, "ALERT": 6, "RATE_LIMIT": 0, "ISOLATE": 24}
    assert bf["mitigation_delay_steps"] == 8.0

    # Web Attack - XSS (50 flows)
    xss = families["WEB ATTACK - XSS"]
    assert xss["sample_count"] == 50
    assert xss["action_counts"] == {"ALLOW": 27, "ALERT": 2, "RATE_LIMIT": 0, "ISOLATE": 21}
    assert xss["mitigation_delay_steps"] == 1.0

    # Web Attack - SQL Injection (10 flows)
    sqli = families["WEB ATTACK - SQL INJECTION"]
    assert sqli["sample_count"] == 10
    assert sqli["action_counts"] == {"ALLOW": 9, "ALERT": 1, "RATE_LIMIT": 0, "ISOLATE": 0}
    assert sqli["mitigation_delay_steps"] == 50.0

    # Zero RATE_LIMIT actions across all stealth families
    for name, fam in families.items():
        assert fam["action_counts"]["RATE_LIMIT"] == 0, f"RATE_LIMIT must be 0 for {name}"

    # Infiltration and SQL Injection trigger zero disruptive isolations
    assert infil["action_counts"]["ISOLATE"] == 0
    assert sqli["action_counts"]["ISOLATE"] == 0


def test_phase2a_baseline_ladder_artifact_consistency():
    """Verify Phase 2A baseline costs strictly match baseline_metrics.json on D_pol_val."""
    b_file = Path("results/phase2/EXP-P2A-BASELINES-001/baseline_metrics.json")
    assert b_file.exists()

    with open(b_file) as f:
        data = json.load(f)

    runs = data["runs"]
    for r in runs:
        assert r["total_flows"] == 142346

    # Standard Enterprise
    std_3 = {r["policy_name"]: r["total_cost"] for r in runs if r["cost_regime"] == "standard_enterprise" and r["action_mode"] == "3-action"}
    std_4 = {r["policy_name"]: r["total_cost"] for r in runs if r["cost_regime"] == "standard_enterprise" and r["action_mode"] == "4-action"}

    assert std_3["Baseline_0_Always_ALLOW"] == 2592800.0
    assert std_3["Baseline_1_Single_Threshold_tau_0.50"] == 440536.0
    assert std_3["Baseline_2_Two_Tier_0.40_0.75"] == 427527.0
    assert std_3["Baseline_3_Heuristic_State_Machine"] == 1806318.0

    assert std_4["Baseline_0_Always_ALLOW"] == 2592800.0
    assert std_4["Baseline_1_Single_Threshold_tau_0.50"] == 371678.5
    assert std_4["Baseline_2_Two_Tier_0.40_0.75"] == 376299.0
    assert std_4["Baseline_3_Heuristic_State_Machine"] == 1196420.0


def test_phase2e_audit_metrics_and_provenance():
    """Verify Phase 2E audit counts and metadata from clean rerun match safety_audit_metrics.json."""
    audit_metrics_file = Path("results/phase2/EXP-P2E-EXPLAINABILITY-001/safety_audit_metrics.json")
    assert audit_metrics_file.exists()

    with open(audit_metrics_file) as f:
        data = json.load(f)

    # Git commit provenance
    assert data["metadata"]["git_commit"].startswith("f9df812")

    # Audit coverage metrics
    metrics = data["audit_metrics"]
    assert metrics["total_steps_evaluated"] == 142346
    assert metrics["non_allow_interventions_count"] == 28167
    assert metrics["audit_cards_generated"] == 28167
    assert metrics["audit_coverage_pct"] == 100.0
    assert metrics["safety_overrides_logged"] == 12573
    assert metrics["rq7_3_pass"] is True

    # Safety gate summary
    gate = data["safety_gate_summary"]
    assert gate["total_evaluations"] == 142346
    assert gate["total_overrides"] == 12573
    assert gate["active_isolated_hosts_count"] == 10
    assert gate["active_rate_limited_hosts_count"] == 10
    assert gate["known_hosts_count"] == 250
    assert gate["reasons"]["CRITICAL_INFRASTRUCTURE_EXEMPTION"] == 147
    assert gate["reasons"]["BLAST_RADIUS_CIRCUIT_BREAKER"] == 12426

