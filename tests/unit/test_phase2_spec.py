"""Tests verifying the Phase 2 research & design specification (Task 2)."""

from pathlib import Path


def test_phase2_specification_structure_and_governance():
    """Verify that the Phase 2 design specification exists and covers required sections."""
    spec_path = Path("docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md")
    assert spec_path.exists(), "Phase 2 design spec docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md must exist"

    content = spec_path.read_text(encoding="utf-8")
    assert len(content) > 5000, "Specification must be comprehensive"

    # Core required sections
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
        assert kw.lower() in content.lower(), f"Keyword '{kw}' must be present in Phase 2 spec"

    # Verify simulation-only and no real network mutation
    assert "simulation-only" in content.lower()
    assert "packet dropping" in content.lower()
    assert "critical infrastructure exemption" in content.lower()
    assert "blast radius circuit breaker" in content.lower()
