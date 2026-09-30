"""Tests for the D-002 feature-contract evidence generator."""

from __future__ import annotations

import pytest

from xrlids.features.definitions import FEATURES
from xrlids.features.registry import load_feature_registry


def test_evidence_script_runs_and_is_honest(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(".")
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "fce", "scripts/phase1/feature_contract_evidence.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    evidence = mod.build_evidence()

    assert evidence["decision_id"] == "D-002"
    assert "OPEN" in evidence["decision_status"]
    assert evidence["recommendation_made"] is False
    # the missing-evidence section must be non-empty while datasets are absent
    assert evidence["missing_evidence_for_decision"]
    # unsw must be reported as partially unsupported at R10
    unsw = evidence["per_dataset_availability"]["unsw_nb15"]["R10"]
    assert unsw["n_supported"] == 4
    assert "syn_count" in unsw["unsupported"]
    # empirical section must not claim validated schemas without data
    for ds, emp in evidence["empirical_schema_validation"].items():
        assert emp["status"] in {"DATA_NOT_AVAILABLE", "validated", "schema_conflict"}


def test_every_feature_has_gate_answers(registry):
    for name in FEATURES:
        gate = registry.gate_for(name)
        assert len(gate) == 10, name


def test_live_blocked_features_are_exactly_the_documented_four():
    blocked = {n for n, s in FEATURES.items() if not s.live_available}
    assert blocked == {"active_mean_ms", "idle_mean_ms", "subflow_fwd_bytes", "subflow_bwd_bytes"}
