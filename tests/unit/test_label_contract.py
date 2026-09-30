"""Label contract tests, including the rule that unknowns are never BENIGN."""

from __future__ import annotations

import pandas as pd
import pytest

from xrlids.labels.contract import UnknownLabelError, apply_label_contract


def test_normalization_handles_spaces_dashes_and_case(contract):
    assert contract.normalize("  benign ") == "BENIGN"
    assert contract.normalize("Web Attack \u2013 Brute Force") == "WEB ATTACK - BRUTE FORCE"
    assert contract.normalize("DoS Hulk") == "DOS HULK"


def test_benign_and_attack_classification(contract):
    assert contract.classify("BENIGN", "cicids2017") == ("BENIGN", 0)
    assert contract.classify("DOS HULK", "cicids2017") == ("ATTACK", 1)


def test_unknown_label_raises_for_classify(contract):
    with pytest.raises(UnknownLabelError):
        contract.classify("TOTALLY NEW ATTACK", "cicids2017")


def test_family_mapping(contract):
    assert contract.family_of("DOS HULK", "cicids2017") == "DoS"
    assert contract.family_of("PORTSCAN", "cicids2017") == "PortScan"
    assert contract.family_of("WEB ATTACK - XSS", "cicids2017") == "Web"


def test_apply_rejects_unknown_and_reports_accounting(contract):
    frame = pd.DataFrame({"Label": ["BENIGN", "DoS Hulk", "Made Up Attack", "PortScan"]})
    app = apply_label_contract(frame, "cicids2017", contract)

    assert app.stats["rows_total"] == 4
    assert app.stats["rows_accepted"] == 3
    assert app.stats["rows_rejected_unknown_label"] == 1
    # the unknown row must NOT be silently labelled benign
    assert app.canonical.tolist()[2] == "UNKNOWN"
    assert app.binary.tolist()[2] == -1
    assert not bool(app.accepted_mask.tolist()[2])


def test_rejection_report_has_required_fields(contract):
    frame = pd.DataFrame({"Label": ["BENIGN", "Made Up Attack", "Made Up Attack"]})
    app = apply_label_contract(frame, "cicids2017", contract)
    assert not app.rejections.empty
    row = app.rejections.iloc[0]
    assert row["row_count"] == 2
    assert row["dataset"] == "cicids2017"
    assert "unknown" in row["reason"].lower() or "allow-list" in row["reason"].lower()


def test_missing_label_column_fails_loudly(contract):
    frame = pd.DataFrame({"NotALabel": [1, 2]})
    with pytest.raises(UnknownLabelError):
        apply_label_contract(frame, "cicids2017", contract)


def test_unknown_dataset_raises(contract):
    with pytest.raises(KeyError):
        contract.classify("BENIGN", "does_not_exist")
