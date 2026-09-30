# Phase 1 — Data + Research + Model Foundation

Objective: establish a defensible and reproducible scientific foundation for XRL-IDARS.

This index lists every Phase 1 document required by the build spec and its current status.
A document is only written when the research it records has actually happened — this index
prevents "documentation after the fact".

| Document | Purpose | Depends on | Status |
| --- | --- | --- | --- |
| `DATASET_PROVENANCE.md` | Source, version, license, checksums per dataset | D-004 (acquire) | ⬜ blocked |
| `DATASET_CATALOG.md` | Human-readable dataset catalogue | audit | ⬜ |
| `DATASET_AUDIT.md` | Findings from `scripts/phase1/01_dataset_audit.py` | D-004 | ⬜ |
| `DATASET_SCHEMAS.md` | Per-column documentation across all datasets | audit | ⬜ |
| `DATA_CLEANING_POLICY.md` | Every removal rule with rationale and risk | audit | ⬜ |
| `LABEL_CONTRACT.md` | Native → normalized → binary → family | audit | ⬜ |
| `FEATURE_TAXONOMY.md` | Grouping and compatibility of features | D-002 | ⬜ blocked |
| `FEATURE_DEFINITIONS.md` | Mathematical definition of every feature | D-002 | ⬜ blocked |
| `FEATURE_COMPATIBILITY.md` | Dataset vs live availability matrix | D-002 | ⬜ blocked |
| `SPLIT_METHODOLOGY.md` | What goes into train/val/test and why | audit | ⬜ |
| `LEAKAGE_AUDIT.md` | Six mandatory leakage checks | splits | ⬜ |
| `METRICS.md` | Formulas and implementation audit | — | ⬜ |
| `RF_METHODOLOGY.md` | RF method + historical-vs-new distinction | features frozen | ⬜ |
| `LSTM_METHODOLOGY.md` | Sequence construction + boundary safety | features frozen | ⬜ |
| `ERROR_ANALYSIS.md` | Top FP/FN, hardest classes, examples | baselines | ⬜ |
| `SHAP_METHODOLOGY.md` | Explainer, sample size, aggregation, limits | baselines | ⬜ |

## Related

- Exit criteria: §93 of the build spec (all Phase 1 items ticked).
- Review gate: `PHASE1_REVIEW.md` (repository root of `docs/`, produced at end of Week 1).
- Open decisions that block Phase 1: D-002, D-003, D-004, D-005.
