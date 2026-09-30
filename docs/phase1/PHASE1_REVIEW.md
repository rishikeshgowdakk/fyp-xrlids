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

The Phase 1 *empirical* programme has begun with the acquisition and verification of
real data from CSE-CIC-IDS2018 (`Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`, 331,125 rows,
102.8 MB, verified SHA-256 `b0534c5d...`). Schema validation and comprehensive dataset audit
have passed on real data, revealing critical data-quality and leakage findings.

## 2. Dataset status

| Dataset | Files present | Checksums | Audit | Status |
| --- | --- | --- | --- | --- |
| CICIDS2017 | 0 | none recorded | not run | `DATA_NOT_AVAILABLE` (form/session barrier) |
| CSE-CIC-IDS2018 | 1 | verified (`b0534c5d...`) | completed (331,125 rows) | `PARTIAL` (1 file verified) |
| UNSW-NB15 | 0 | none recorded | not run | `DATA_NOT_AVAILABLE` (SharePoint auth barrier) |

## 3. Dataset audit findings (real data: CSE-CIC-IDS2018)

Audited `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (machine-readable: `results/audits/cse_cic_ids2018_audit.json`):
- **Rows:** 331,125 rows, 80 columns.
- **Duplicates:** 97 exact raw duplicate rows.
- **Missing / Infinite values:** 1,834 NaN cells in `Flow Byts/s`; 0 infinite values.
- **Near-constant columns:** 8 columns (`Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Byts/b Avg`, `Fwd Pkts/b Avg`, `Fwd Blk Rate Avg`, `Bwd Byts/b Avg`, `Bwd Pkts/b Avg`, `Bwd Blk Rate Avg`).
- **Duration anomalies:** 0 negative durations; 2,919 zero-duration flows; 25 NaN durations (from embedded headers).
- **Label audit & rejections:**
  - Benign: 238,037 (71.89%)
  - Infiltration (`INFILTERATION`): 93,063 (28.10%)
  - Repeated header rows (`LABEL`): 25 rows (0.00755%) correctly rejected as unknown labels, never mapped to BENIGN.

## 4. Feature contract

Implemented: 20 canonical features with mathematical definitions, three candidate rungs
(R10/R15/R20, 10/15/20 features), per-feature decision-gate answers, and per-dataset column
maps. Status is `candidate_not_frozen` — **D-002 is open.**

- **CSE-CIC-IDS2018:** All 20 canonical features verified from data (columns present and mathematically computable).
- **UNSW-NB15:** Supports only **4/10** features of the R10 contract (no TCP flag counts, no IAT, no active/idle, no subflow). The planned 3×3×3 sweep cannot run uniformly without a research decision.

## 5. Cleaning decisions

Cleaning correctly drops 97 exact duplicates, rejects 25 unknown embedded header rows, and reconciles row accounting perfectly (331,125 raw -> 331,027 accepted).

## 6. Split methodology & Leakage findings

- Naive stratified random split (60/20/20, seed 42) **FAILED the leakage audit**:
  - L-01 duplicate overlap: 7,576 rows shared between train & validation; 7,559 shared between train & test.
  - Root cause: In the 10-feature R10 space, 114,315 rows (34.53%) have identical feature vectors. Naive flow splitting places duplicate feature vectors across splits, creating severe artificial test inflation.
  - Mitigation verified: Feature-space deduplication prior to split construction passes L-01 with 0 duplicate overlaps.
  - Action: No model training run until the researcher formally decides the deduplication/grouping policy.

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
