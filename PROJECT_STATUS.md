# PROJECT STATUS

Last updated: 2026-09-30
Phase: **1 — Data + Research + Model Foundation**

Legend: ✅ done · 🟡 in progress · ⛔ blocked on research decision · ⬜ not started

---

## Phase 1 — Week 1

| Item | Status | Evidence / artifact |
| --- | --- | --- |
| Repository structure | ✅ | this tree |
| Project scope | ✅ | `docs/00_PROJECT/PROJECT_SCOPE.md` |
| Research questions | ✅ | `docs/00_PROJECT/RESEARCH_QUESTIONS.md` |
| System objectives | ✅ | `docs/00_PROJECT/SYSTEM_OBJECTIVES.md` |
| Requirements (FR/NFR) | ✅ | `docs/01_REQUIREMENTS/` |
| Decision log | ✅ | `docs/03_DECISIONS/DECISION_LOG.md` |
| Claims registry | ✅ | `docs/03_DECISIONS/CLAIMS_REGISTRY.md` |
| Assumption registry | ✅ | `docs/03_DECISIONS/ASSUMPTIONS.md` |
| Dataset registry | ✅ (skeleton) | `data/manifests/dataset_registry.yaml` |
| Feature registry | ✅ (skeleton) | `configs/features/features.yaml` |
| Experiment registry | ✅ (skeleton) | `docs/experiments/EXPERIMENT_REGISTRY.md` |
| Documentation templates | ✅ | `docs/templates/` |
| Dataset acquisition | ⛔ | requires user decision (see below) |
| Dataset audit | ⬜ | `scripts/phase1/01_dataset_audit.py` |
| Schema documentation | ⬜ | `docs/phase1/DATASET_SCHEMAS.md` |
| Label contract freeze | ⬜ | `configs/labels/label_mapping.yaml` |
| Feature contract freeze | ⛔ | requires user decision |
| Cleaning policy | ⬜ | `docs/phase1/DATA_CLEANING_POLICY.md` |
| Splits + leakage audit | ⬜ | `docs/phase1/SPLIT_METHODOLOGY.md` |
| RF baseline | ⬜ | — |
| LSTM baseline | ⬜ | — |
| Fusion | ⬜ | — |
| Threshold + calibration | ⛔ | requires primary-objective decision |
| Feature sweep (R10/R15/R20) | ⬜ | — |
| Cross-dataset (6 directions) | ⬜ | — |
| OOD / unseen attack | ⬜ | — |
| SHAP | ⬜ | — |
| Phase 1 review | ⬜ | `PHASE1_REVIEW.md` |

## Phase 2 — Week 2

All items ⬜. See `docs/phase2/`.

## Phase 3 — Week 3

All items ⬜. See `docs/phase3/`.

---

## Blocked on research decisions

These are recorded as open decisions in `docs/03_DECISIONS/DECISION_LOG.md`.
Per the complication protocol (§80 / §83 of the build spec), the agent **does not**
resolve these silently.

| ID | Blocking | Decision needed |
| --- | --- | --- |
| D-002 | Feature contract freeze | Confirm R10/R15/R20 composition or authorise re-derivation from first principles |
| D-003 | Thresholding | Primary operational objective: max-F1 vs min-FPR vs min-FNR vs cost-sensitive |
| D-004 | Data acquisition | Which datasets to acquire, from which mirrors, and storage budget |
| D-005 | Cross-dataset normalization | Whether any cross-dataset alignment is performed (and if so, what) |
| D-006 | Flow timeout policy | TCP-FIN/RST vs timeout vs window vs hybrid (blocks Phase 3) |

---

## What was explicitly NOT done

- No dataset rows were fabricated to produce an accuracy number.
- No historical metric was carried into this repo as a "result".
- Historical values are quarantined in `docs/04_QUESTIONS/HISTORICAL_RESULTS.md`
  and labelled *historical — not reproduced*.
- No model has been trained yet.
