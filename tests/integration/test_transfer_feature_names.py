"""Regression test ensuring no obsolete feature names appear in generated reports (Task 10)."""

from __future__ import annotations

from pathlib import Path
import pytest

OBSOLETE_FEATURE_NAMES = [
    "flow_pkts_per_s",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "fin_flag_count",
    "pkt_len_std",
    "fwd_packets_count",
]


def test_no_obsolete_feature_names_in_generated_reports():
    """Verify that none of the obsolete feature names appear in any generated markdown report."""
    reports_dir = Path("reports/generated")
    assert reports_dir.is_dir(), "reports/generated directory does not exist"

    md_files = list(reports_dir.glob("*.md"))
    assert len(md_files) > 0, "No markdown reports found in reports/generated"

    violations: list[str] = []
    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8")
        for obsolete in OBSOLETE_FEATURE_NAMES:
            if f"`{obsolete}`" in content or f" {obsolete} " in content:
                violations.append(f"{md_file.name} contains obsolete feature name: {obsolete}")

    assert not violations, f"Found obsolete feature names in generated reports:\n" + "\n".join(violations)
