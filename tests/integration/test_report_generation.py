"""Tests for Phase 1 comprehensive report generation."""

from pathlib import Path
import subprocess
import sys


def test_generate_reports_script():
    """Ensure scripts/phase1/generate_reports.py runs and produces all required reports."""
    cmd = [sys.executable, "scripts/phase1/generate_reports.py"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert res.returncode == 0

    expected_reports = [
        "dataset_manifest.md",
        "audit_report.md",
        "feature_compatibility.md",
        "leakage_report.md",
        "split_report.md",
        "model_report.md",
        "comparison_report.md",
        "error_analysis.md",
        "shap_report.md",
        "transfer_report.md",
        "phase1_final_report.md",
    ]

    out_dir = Path("reports/generated")
    for rep in expected_reports:
        p = out_dir / rep
        assert p.exists(), f"Report {rep} was not generated"
        content = p.read_text(encoding="utf-8")
        assert len(content) > 100, f"Report {rep} is too short"
        assert "#" in content

    # Test taxonomy presence in final report
    final_report = (out_dir / "phase1_final_report.md").read_text(encoding="utf-8")
    for token in ["VERIFIED", "EMPIRICALLY OBSERVED", "DATA_NOT_AVAILABLE", "RESEARCH DECISION REQUIRED"]:
        assert token in final_report, f"Taxonomy token {token} missing from final report"
