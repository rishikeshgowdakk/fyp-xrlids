"""Tests verifying the Phase 2 research & design specification (Task 2 & Review)."""

from pathlib import Path


def test_phase2_specification_structure_and_governance():
    """Verify Phase 2 specification structure, D-003 governance, isolation, and safety boundaries."""
    spec_path = Path("docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md")
    assert spec_path.exists(), "Phase 2 design spec docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md must exist"

    content = spec_path.read_text(encoding="utf-8")
    assert len(content) > 5000, "Specification must be comprehensive"
    lowered = content.lower()

    # 1. Core required sections
    required_keywords = [
        "Problem Definition",
        "RQ7",
        "Frozen Detector Interface",
        "Minimum Justified State Representation",
        "Candidate Action Space",
        "Offline Response Simulator",
        "Cost & Reward Model",
        "Deterministic Baseline Policies",
        "Reinforcement Learning Formulation",
        "Evaluation Protocol",
        "Experimental Isolation",
        "Robustness Experiments",
        "Dual-Layer Explainability",
        "Deterministic Safety Architecture",
        "Implementation Roadmap",
    ]
    for kw in required_keywords:
        assert kw.lower() in lowered, f"Keyword '{kw}' must be present in Phase 2 spec"

    # 2. D-003 Governance & Cost Model Semantics
    # D-003 must not be claimed as resolved by the Phase 2 cost matrix; operational threshold remains open
    assert "resolving decision d-003" not in lowered
    assert "operational threshold selection remains explicitly open" in lowered or "operational threshold selection open" in lowered
    assert "illustrative research cost framework" in lowered
    assert "research assumptions" in lowered
    assert "not select or resolve the real deployment threshold" in lowered

    # 3. Probability overclaim removal & Continuous detector risk score contract
    assert "posterior probability" not in lowered
    assert "continuous attack risk score" in lowered
    assert "calibrated probability is reported only where an explicit platt calibration artifact is applied" in lowered

    # 4. Strict Dataset Isolation Protocol & Simulation-Only Boundaries
    assert "final policy test population" in lowered
    assert "completely untouched until final evaluation" in lowered
    assert "designated policy-training portion" in lowered
    assert "designated policy-validation portion" in lowered
    assert "simulated transition assumptions" in lowered
    assert "delayed compromise accumulation" in lowered
    assert "simulation-only" in lowered
    assert "packet dropping" in lowered
    assert "critical infrastructure exemption" in lowered
    assert "blast radius circuit breaker" in lowered

    # 5. Pre-registered research criteria & Neutral Null Hypothesis acceptance
    assert "pre-registered proposed research study criteria" in lowered
    assert "neutral null hypothesis acceptance" in lowered
