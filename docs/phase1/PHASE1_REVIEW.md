# PHASE 1 REVIEW

Status: **PARTIALLY COMPLETE — implementation complete, empirical results pending datasets.**

This review reports what actually exists. Where an experiment has not run, it says so.
No metric in this document is a dataset result.

---

## 1. Executive summary

The Phase 1 *implementation* is complete and executable: data provenance, auditing, label
contract, feature contract, cleaning, leakage-audited splitting, preprocessing, RF, LSTM,
fusion, calibration, threshold analysis, SHAP/error-analysis infrastructure, experiment
registry, artifact metadata, centralized metrics, a CLI and an automated test suite.

The Phase 1 *empirical* programme has not run, because **no datasets are present** in the
repository. Every result-producing experiment therefore reports `DATA_NOT_AVAILABLE`.
The pipeline has been executed end-to-end on synthetic fixtures to prove it runs; those
outputs are labelled `SMOKE_ONLY` and are explicitly not evidence.

## 2. Dataset status

| Dataset | Files present | Checksums | Audit | Status |
| --- | --- | --- | --- | --- |
| CICIDS2017 | 0 | none recorded | not run | `DATA_NOT_AVAILABLE` |
| CSE-CIC-IDS2018 | 0 | none recorded | not run | `DATA_NOT_AVAILABLE` |
| UNSW-NB15 | 0 | none recorded | not run | `DATA_NOT_AVAILABLE` |

## 3. Dataset audit findings

None — no data. The auditor is implemented and unit-tested (`tests/data/test_audit.py`) on
fixtures, including NaN/Inf counting, duplicate detection, negative-duration detection,
schema-variation detection and unknown-label reporting.

## 4. Feature contract

Implemented: 20 canonical features with mathematical definitions, three candidate rungs
(R10/R15/R20, 10/15/20 features), per-feature decision-gate answers, and per-dataset column
maps. Status is `candidate_not_frozen` — **D-002 is open.**

**Key finding:** UNSW-NB15 supports only **4/10** features of the R10 contract (no TCP flag
counts, no IAT, no active/idle, no subflow). The 3×3×3 sweep is therefore evaluable only
2/3 at R10. The pipeline returns `BLOCKED_FEATURE_INCOMPATIBLE` rather than substituting
columns. This needs a project decision (see FEATURE_COMPATIBILITY.md).

## 5. Cleaning decisions

Five documented rules with problem/detection/affected/action/reason/risk/alternative, plus
an arithmetic reconciliation that fails loudly if rows are unexplained. Vendor Infinity rate
columns are never used (rates are recomputed from source quantities).

## 6. Split methodology

`stratified_random` 60/20/20, seed 42. Candidate, not frozen. Temporal/grouped splits are not
used because no trustworthy grouping/timestamp key is assumed to exist until the audit says
otherwise.

## 7. Leakage findings

L-01/L-02/L-06 implemented and enforced; L-03/L-04/L-05 implemented but **not performed** on
fixture runs (no group/source-IP/timestamp columns), and therefore not yet verified for the
real datasets. L-02 is a rounding proxy and is documented as incomplete.

## 8. RF results

Not run. Implementation complete and unit-tested (continuous probability output, feature
order enforcement, single-class rejection).

## 9. LSTM results

Not run. Implementation complete and unit-tested. **Sequence safety verified
programmatically**: no sequence can cross a train/validation/test boundary.

## 10. RF vs LSTM comparison

Infrastructure complete: comparison is performed on the **aligned intersection** of the two
score populations, and the alignment report records how many rows each model scored and how
many were dropped. On the fixture this correctly showed RF scoring 300 rows vs LSTM 296
(sequence windows), fusing on 296. No dataset result.

## 11. Fusion results

Implementation complete (`alpha * rf + (1-alpha) * lstm`, alpha configurable, default 0.5).
Fusion is not assumed to help; `compare_components` reports RF, LSTM and Fusion side by side
on one population.

## 12. Calibration findings

Implementation complete: reliability curve, Brier score, ECE, and validation-only Platt
scaling. No dataset finding. Important caveat retained: a score is not called "confidence"
until ECE supports it.

## 13. Threshold analysis

Implementation complete: full 0.00–1.00 sweep plus candidate operating points for
max-F1 / min-FPR-subject-to-recall / min-FNR-subject-to-FPR / cost-sensitive.
**No threshold has been frozen** — D-003 is open. Every result states the threshold used.

## 14. Feature sweep

Not run (blocked by D-002 and by data availability; partially impossible for UNSW-NB15 at R10).

## 15. Cross-dataset results

Not run. Only the "source-trained preprocessing applied unchanged to target" option is
implemented; normalisation strategy is D-005 and remains open.

## 16. OOD results

Not run — infrastructure partially available via the label-family column, but no experiment
executed.

## 17. SHAP findings

Not run. Methodology (attribution not causality) is documented; the SHAP module is the
remaining implementation item.

## 18. Error analysis

Not run. `results/error_analysis/` is defined; the analyzer is not yet written.

## 19. Reproducibility status

Environment pinned (`requirements.txt`, `pyproject.toml`); Python 3.14.4; artifact metadata
records Git commit, dataset SHA-256, feature-schema hash, seed and environment fingerprint.
Datasets are not checksum-pinned yet (none acquired).

## 20. Known limitations

- No datasets ⇒ no empirical claims whatsoever.
- Column maps are `unverified_pending_audit`.
- Near-duplicate leakage detection is a proxy.
- Group/temporal/source-IP leakage checks have not run against real data.
- Only a stratified split is implemented; temporal/grouped splits are future work.

## 21. Unresolved decisions

| ID | Decision | Blocks |
| --- | --- | --- |
| D-002 | Feature contract R10/R15/R20 | feature sweep, baselines, SHAP |
| D-003 | Threshold objective | freezing any operating point |
| D-004 | Dataset acquisition | everything empirical |
| D-005 | Cross-dataset normalisation | transfer experiments |
| — | UNSW-NB15 R10 incompatibility | 1/3 of the primary sweep |

## 22. Failed experiments

None executed, therefore none failed. One **test** failure was found and fixed during
development (an incorrect expectation about fixture row indices, not a code defect).

## 23. Negative findings

- UNSW-NB15 cannot satisfy the R10 contract. This is a genuine, reportable negative result
  about the *design*, discovered before any training was run.
- Zero-duration flows are not rare in principle: the rate features are legitimately
  undefined for them, which forces an explicit row-level policy rather than silent NaN.

## 24. What Phase 2 requires

A frozen feature contract (D-002), a frozen operating threshold (D-003), acquired and
audited datasets (D-004), trained and registered models, and calibration results before any
DQN state or response policy is built.

## 25. What cannot yet be claimed

Nothing about detection performance. Specifically, no accuracy, precision, recall, F1,
ROC-AUC, PR-AUC, confusion matrix, cross-dataset behaviour, SHAP attribution or calibration
result is currently supported by this repository. The `CLAIMS_REGISTRY.md` remains empty of
verified claims by design.
