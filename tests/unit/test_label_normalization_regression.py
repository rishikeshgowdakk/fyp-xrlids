"""Regression tests for the label-normalization corruption discovered in the audit.

Historical defect: ``configs/labels/label_mapping.yaml`` contained an empty-string
replacement key (``"" -> "-"``). The replacement table is applied with ``str.replace``
before any other normalisation, so the empty key was inserted between every character:

    normalize("BENIGN") == "-B-E-N-I-G-N-"

Every test in this file exists to make that class of defect impossible to reintroduce
silently: the table is validated at contract load, corrupting tables fail loudly, and
the documented transformations are pinned to exact expected outputs.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest
import yaml

from xrlids.labels.contract import (
    InvalidReplacementTableError,
    LabelContract,
    UnknownLabelError,
    apply_label_contract,
    load_label_contract,
    validate_replacements,
)

MAPPING_PATH = Path("configs/labels/label_mapping.yaml")

# Task-1 required transformations (exact).
SPEC_EXAMPLES = [
    ("BENIGN", "BENIGN"),
    (" benign ", "BENIGN"),
    ("DoS Hulk", "DOS HULK"),
    ("Web Attack \u2013 XSS", "WEB ATTACK - XSS"),
]

# Representative raw labels captured from the ACTUAL files on this machine
# (2026-10-02, 100k-row prefix scan of every registered CSV). These pin the
# contract against real-world spellings, not synthetic guesses.
REAL_LABELS: dict[str, list[str]] = {
    "cicids2017": [
        "BENIGN", "Bot", "DDoS", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
        "FTP-Patator", "Infiltration", "PortScan",
        "Web Attack \ufffd Brute Force", "Web Attack \ufffd Sql Injection",
        "Web Attack \ufffd XSS",
    ],
    "cse_cic_ids2018": [
        "Benign", "Bot", "Brute Force -Web", "Brute Force -XSS", "DDOS attack-HOIC",
        "DDOS attack-LOIC-UDP", "DDoS attacks-LOIC-HTTP", "DoS attacks-GoldenEye",
        "DoS attacks-Hulk", "DoS attacks-SlowHTTPTest", "DoS attacks-Slowloris",
        "FTP-BruteForce", "SQL Injection",
        "Label",  # repeated-header artifact present in real files
    ],
    "unsw_nb15": [
        "Normal", "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers", "Generic",
        "Reconnaissance", "Shellcode", "Worms",
    ],
}


# --------------------------------------------------------------------------- spec
@pytest.mark.parametrize("raw,expected", SPEC_EXAMPLES)
def test_documented_transformations(contract, raw, expected):
    assert contract.normalize(raw) == expected


def test_benign_is_never_character_shattered(contract):
    """The discovered corruption: '' replacement key turned BENIGN into -B-E-N-I-G-N-."""
    for raw in ["BENIGN", "Benign", " benign ", "  BENIGN\t", "NORMAL", " normal "]:
        got = contract.normalize(raw)
        assert got == got.replace("-", "") or got in {"BENIGN", "NORMAL"}, (
            f"normalize({raw!r}) produced {got!r}; an empty/character-level replacement "
            "key is corrupting labels again"
        )
    assert contract.normalize("BENIGN") == "BENIGN"


def test_normalization_is_deterministic_and_idempotent(contract):
    for raw in ["BENIGN", " benign ", "DoS Hulk", "Web Attack \u2013 XSS", "Label"]:
        once = contract.normalize(raw)
        twice = contract.normalize(raw)
        assert once == twice
        assert contract.normalize(once) == once, "normalize must be idempotent"


# ------------------------------------------------------- replacement table safety
def test_real_config_has_no_invalid_replacement_keys():
    data = yaml.safe_load(MAPPING_PATH.read_text(encoding="utf-8"))
    table = data["normalization"]["unicode_replacements"]
    # Would raise InvalidReplacementTableError on an empty/whitespace/single-char key.
    validate_replacements(table)
    assert "" not in table, "empty replacement key must never exist in the config"


@pytest.mark.parametrize(
    "table",
    [
        {"": "-"},                 # the exact historical defect
        {"   ": "-"},              # whitespace-only key == per-character corruption
        {"a": "b"},                # single ASCII alnum key
        {" ": "-"},                # single ASCII space key
        {"x" * 33: "-"},           # sentence-length key (paste error)
        {"\u2013": "\u2013"},      # identity mapping (no-op / config mistake)
    ],
)
def test_unsafe_replacement_tables_fail_loudly(table):
    with pytest.raises(InvalidReplacementTableError):
        validate_replacements(table)


def test_non_mapping_replacement_table_rejected():
    with pytest.raises(InvalidReplacementTableError):
        validate_replacements(["\u2013", "-"])
    with pytest.raises(InvalidReplacementTableError):
        validate_replacements("\u2013")


def test_non_string_entries_rejected():
    with pytest.raises(InvalidReplacementTableError):
        validate_replacements({"\u2013": 1})
    with pytest.raises(InvalidReplacementTableError):
        validate_replacements({1: "-"})


def test_empty_table_is_allowed_and_none_is_allowed():
    assert validate_replacements({}) == {}
    assert validate_replacements(None) == {}


def test_contract_load_fails_loudly_on_corrupt_table(tmp_path):
    """A YAML with the historical empty key must be rejected at contract load."""
    bad = {
        "contract_version": "0.0.1",
        "status": "invalid",
        "binary": {"benign_tokens": ["BENIGN"]},
        "normalization": {"unicode_replacements": {"": "-"}},
        "datasets": {},
    }
    p = tmp_path / "bad_mapping.yaml"
    p.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(InvalidReplacementTableError):
        LabelContract.from_file(p)


def test_loaded_contract_replacements_are_safe(contract):
    assert "" not in contract.replacements
    for key in contract.replacements:
        assert key.strip() != ""
        assert not (len(key) == 1 and key.isascii() and (key.isalnum() or key.isspace()))


# ------------------------------------------------------------ declared mappings
def test_every_declared_family_map_key_classifies_as_attack(contract):
    """Each dataset's allow-list must classify its own declared attack keys."""
    for dataset, spec in contract.datasets.items():
        benign = {contract.normalize(t) for t in spec.get("benign_labels", [])}
        benign |= contract.benign_tokens
        for key, family in (spec.get("family_map") or {}).items():
            norm = contract.normalize(key)
            if norm in benign:
                # A benign token declared in family_map is a guard entry, not an attack.
                assert contract.classify(norm, dataset) == ("BENIGN", 0)
                continue
            assert contract.classify(norm, dataset) == ("ATTACK", 1), (
                f"{dataset}: declared attack label {key!r} did not classify"
            )
            assert contract.family_of(norm, dataset) == family


def test_real_representative_labels_are_never_corrupted(contract):
    """Labels captured from the real files must normalize to their documented form."""
    assert contract.normalize("BENIGN") == "BENIGN"
    assert contract.normalize("Benign") == "BENIGN"
    assert contract.normalize("Normal") == "NORMAL"
    assert contract.normalize("DoS Hulk") == "DOS HULK"
    assert contract.normalize("DoS attacks-Hulk") == "DOS ATTACKS-HULK"
    assert contract.normalize("Web Attack \ufffd XSS") == "WEB ATTACK - XSS"
    assert contract.normalize("DDOS attack-HOIC") == "DDOS ATTACK-HOIC"


@pytest.mark.parametrize("dataset", sorted(REAL_LABELS))
def test_real_representative_labels_classify_or_reject(contract, dataset):
    """Every real raw label either classifies per the contract or is rejected.

    Rejection is allowed only for genuine artifacts (e.g. the repeated-header
    value ``Label``); it must never silently become BENIGN.
    """
    spec = contract.datasets[dataset]
    benign = {contract.normalize(t) for t in spec.get("benign_labels", [])} | contract.benign_tokens
    for raw in REAL_LABELS[dataset]:
        norm = contract.normalize(raw)
        assert norm != "", f"{dataset}: {raw!r} normalized to empty string"
        try:
            canonical, binary = contract.classify(norm, dataset)
        except UnknownLabelError:
            # Only the repeated-header artifact is an expected rejection.
            assert raw.strip() == "Label", (
                f"{dataset}: real label {raw!r} is rejected but is not a known artifact"
            )
            assert norm not in benign
            continue
        if norm in benign:
            assert (canonical, binary) == ("BENIGN", 0)
        else:
            assert (canonical, binary) == ("ATTACK", 1)
            assert contract.family_of(norm, dataset) in contract.attack_families


def test_unknown_labels_are_rejected_never_benign(contract):
    frame = pd.DataFrame({"Label": ["BENIGN", "Completely Invented", "", "Label"]})
    app = apply_label_contract(frame, "cicids2017", contract)
    assert app.canonical.tolist()[0] == "BENIGN"
    for i in (1, 2, 3):
        assert app.canonical.tolist()[i] == "UNKNOWN", (
            "unknown labels must be rejected as UNKNOWN, never mapped to BENIGN"
        )
        assert app.binary.tolist()[i] == -1
        assert not bool(app.accepted_mask.tolist()[i])


def test_corrupted_normalization_would_be_caught_by_apply(contract):
    """End-to-end guard: a shattering bug would reject 100% of real benign rows."""
    frame = pd.DataFrame({"Label": ["BENIGN"] * 20 + ["DoS Hulk"] * 5})
    app = apply_label_contract(frame, "cicids2017", contract)
    assert app.stats["rows_rejected_unknown_label"] == 0
    assert app.stats["benign_rows"] == 20
    assert app.stats["attack_rows"] == 5
