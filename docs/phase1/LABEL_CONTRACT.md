# LABEL CONTRACT

Status: **implemented** in `src/xrlids/labels/contract.py`; contract data in
`configs/labels/label_mapping.yaml` (`status: unverified_pending_audit`).

## Chain

```text
native label -> normalized label -> canonical {BENIGN, ATTACK} -> attack family
```

Normalization: unicode NFKC, configured replacements (en/em dash → hyphen), strip configured
characters, collapse whitespace, uppercase. This is what turns
`" Web Attack – Brute Force"` into `WEB ATTACK - BRUTE FORCE`.

## Binary mapping

| Canonical | Binary |
| --- | --- |
| BENIGN / NORMAL | 0 |
| ATTACK | 1 |
| UNKNOWN | **rejected** (binary = -1, row not accepted) |

## Unknown-label rule (scientific RULE 3)

A label is accepted only if it is a declared benign label **or** a key in the dataset's
known-attack allow-list. Anything else is UNKNOWN and is:

1. **not** mapped to BENIGN (or ATTACK);
2. counted and reported in `results/audits/label_rejections.csv` with fields
   `dataset, original_label, normalized_label, row_count, percentage, reason`;
3. excluded from the modelling population.

## Taxonomies are per-dataset and not assumed equivalent

| Dataset | Label source | Notes |
| --- | --- | --- |
| CICIDS2017 | `Label` | leading-space and en-dash artifacts handled by normalization |
| CSE-CIC-IDS2018 | `Label` | longer attack names (e.g. `DoS attacks-Hulk`), separate taxonomy |
| UNSW-NB15 | numeric `label` + categorical `attack_cat` | wholly different taxonomy (Generic, Exploits, Fuzzers, …) |

The same family name across datasets may cover different underlying attacks. Where that is
the case it is documented rather than flattened; unresolved mappings currently fall back to
`Other` rather than being forced into a wrong family.

## Verification status

The label sets above are documented from public dataset descriptions and are **unverified**.
The audit confirms them against the real files and reports every unknown label with its row
count. A wrong contract entry therefore produces an unexpected rejection count rather than
silently mislabelled data.

## Preserved for secondary analysis

`native_label`, `normalized_label`, `canonical_label` and `attack_family` are all retained,
so multiclass analysis (per-attack error analysis, unseen-attack experiments) remains
possible even though the primary detector is binary.
