# PHASE 1 REVIEW

Status: **PARTIALLY COMPLETE — implementation complete, initial empirical baseline observed on CSE-CIC-IDS2018, multi-dataset programme pending remaining data.**

This review reports what actually exists. Where an experiment has not run, it says so.
Empirical metrics reported reflect the verified single day file of CSE-CIC-IDS2018 (`Thursday-01-03-2018`).

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

Empirical baseline executed on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`). On the 43,340-row deduplicated test split (Policy A, threshold 0.5): Accuracy 0.6479, Precision 0.3206, Recall 0.4742, F1 0.3826, Specificity 0.6998, FPR 0.3002, ROC-AUC 0.6443, PR-AUC 0.4140. Results are scoped to this verified day file.

## 9. LSTM results

Empirical sequence classifier executed on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`, $T=5$, boundary-safe). On test sequences: Accuracy 0.7938, Precision 0.7390, Recall 0.1602, F1 0.2633, Specificity 0.9831, FPR 0.0169, ROC-AUC 0.7284, PR-AUC 0.4860. Demonstrates a dramatic reduction in false alarm rate (FPR 0.0169 vs RF 0.3002).

## 10. RF vs LSTM comparison

Evaluated on the aligned test population (43,336 rows). Model disagreement rate: 32.97% (14,287 rows). RF predicted attack while LSTM predicted benign on 13,436 rows (RF false alarm on 9,809 benign rows; RF correct on 3,627 attack rows). LSTM predicted attack while RF predicted benign on 851 rows (LSTM correct on 496 attack rows; false alarm on 355 rows).

## 11. Fusion results

RF + LSTM score fusion ($\alpha=0.30$, tuned strictly on validation ROC-AUC). On aligned test data: Accuracy 0.7978, Precision 0.7640, Recall 0.1750, F1 0.2848, Specificity 0.9838, FPR 0.0162, ROC-AUC 0.7452, PR-AUC 0.5151. Error analysis confirms 10,478 samples were successfully rescued by fusion when one individual model failed, with 0 dual-correct degradations.

## 12. Calibration findings

Platt scaling, ECE, Brier score, and reliability curves computed on validation and test splits (`EXP-P1-CSE2018-R10-001/calibration_report.json`). Validation Platt-calibrated RF and Fusion models evaluated on test. Caveat retained: raw model scores are not called "confidence" until supported by calibration analysis.

## 13. Threshold analysis

Validation threshold sweep (0.00–1.00) completed. Candidate operating points computed for max-F1, min-FPR at recall floor, min-FNR at FPR cap, and cost-sensitive objectives (`threshold_candidates.json`). Neutral 0.5 threshold reported in baseline tables; **no operational threshold has been frozen** (D-003 remains open).

## 14. Feature sweep

Full 27-condition sweep remains blocked by D-002, UNSW-NB15 R10 incompatibility, and pending acquisition of CIC-IDS2017/UNSW-NB15 datasets.

## 15. Cross-dataset results

Programmatic 4-feature common transfer contract implemented in `src/xrlids/features/registry.py`. Source-side training and evaluation on CSE-CIC-IDS2018 recorded in `EXP-P1-TRANSFER-CSE-TO-UNSW-001`. Target evaluation on UNSW-NB15 is pending dataset acquisition (`DATA_NOT_AVAILABLE`). Normalization strategy D-005 remains open.

## 16. OOD results

Not run — infrastructure ready via the label-family taxonomy, but blocked on additional datasets.

## 17. SHAP findings

TreeSHAP attribution computed on CSE-CIC-IDS2018 Random Forest (`EXP-P1-CSE2018-R10-001`). Top three predictive drivers: `packet_length_std` (mean |SHAP|=0.0309), `rst_count` (0.0294), and `flow_duration_ms` (0.0273). Caveat preserved: attribution quantifies model feature reliance, not physical network causality.

## 18. Error analysis

Deterministic error analyzer implemented in `src/xrlids/evaluation/error_analysis.py` and executed for `EXP-P1-CSE2018-R10-001`, producing confidence distributions, hardest misclassified rows, duplicate-mask annotations, and fusion interaction breakdowns.

## 19. Reproducibility status

Environment pinned (`requirements.txt`, `pyproject.toml`); Python 3.14.4; artifact metadata records Git commit, dataset SHA-256, feature-schema hash, seed and environment fingerprint. CSE-CIC-IDS2018 day file verified by SHA-256 (`b0534c5d...`).

## 20. Known limitations

- Empirical results currently reflect one verified file of CSE-CIC-IDS2018 (`Thursday-01-03-2018`).
- CIC-IDS2017 and UNSW-NB15 datasets are not yet acquired in the manifest.
- Near-duplicate leakage detection uses a rounding proxy.
- Group/temporal/source-IP leakage checks require explicit metadata columns not present in the current single file.
- Primary feature contract (D-002) and threshold objective (D-003) remain open research decisions.

## 21. Unresolved decisions

| ID | Decision | Blocks |
| --- | --- | --- |
| D-002 | Feature contract R10/R15/R20 | Full 27-condition feature sweep, multi-dataset baselines |
| D-003 | Threshold objective | Freezing single operational operating point |
| D-004 | Dataset acquisition | Remaining empirical work for CIC-IDS2017 and UNSW-NB15 |
| D-005 | Cross-dataset normalisation | Target evaluation on transferred feature spaces |
| — | Duplicate-Split Policy | Formal adoption of Policy A (`deduplicate_features`) vs Policy B |
| — | UNSW-NB15 R10 incompatibility | 1/3 of primary feature sweep |

## 22. Failed experiments

None failed due to pipeline defects. Synthetic smoke test passed (`results/smoke/smoke_R10.json`).

## 23. Negative findings

- UNSW-NB15 cannot satisfy the R10 contract (4/10 features supported).
- Zero-duration flows occur (2,919 flows), causing undefined rate features that require explicit NaN handling rather than silent imputation.
- Naive flow splitting on tabular features leads to severe duplicate leakage (34.53% duplicate feature vectors).

## 24. What Phase 2 requires

A formally frozen feature contract (D-002), a frozen operating threshold (D-003), acquired and audited datasets for all three domains (D-004), and full cross-dataset transfer validation before any DQN response policy is built.

## 25. What cannot yet be claimed

No claim of universal or cross-dataset intrusion detection accuracy. No claim that findings from one CSE-CIC-IDS2018 capture day apply identically to different network topologies. No claim of live real-time detection without ground truth. Claims in `CLAIMS_REGISTRY.md` are strictly limited to verified, reproducible single-dataset artifacts under `results/experiments/`.
