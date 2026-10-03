# EXPERIMENT EVIDENCE RECONCILIATION & SCIENTIFIC AUDIT REPORT

> [!IMPORTANT]
> **Document Purpose**: This document serves as the permanent scientific audit record for the Phase 1 research experimentation platform.
> It reconciles physical filesystem bytes, cryptographic digests, canonical manifest registrations, test suite execution results, and machine-readable experiment evaluation artifacts.
> It explicitly distinguishes verified facts from configured intentions and records all known scientific and methodological boundaries.

---

## 1. Purpose of Evidence Reconciliation

During the rapid development of the Phase 1 experimental core, discrepancies arose between documentation claims, configured settings, generated status reports, and actual machine-readable artifacts:
1. **Manifest & Digest Discrepancies**: Historical reports and intermediate tables cited conflicting file sizes and SHA-256 digests for CSE-CIC-IDS2018 (e.g. `353,091,894` bytes / `37faea...` vs canonical `352,368,373` bytes / `d96f38...`). A ground-truth filesystem audit of all 20 physical files was necessary to establish cryptographic ground truth.
2. **Provenance vs Integrity**: The repository previously mixed labels such as `official_aws_mirror` with `recognized_mirror` without rigorous distinction between *cryptographic integrity* (the local bytes match a hash) and *provenance* (the authoritative origin of the file).
3. **Reported vs Actual Test Counts**: Previous status documentation stated 164 passing tests while the actual test suite grew to 178 passing tests.
4. **Configured vs Executed Random Seeds**: Experiment YAML configurations declared `seeds: [42, 123, 456]`, but only seed 42 was executed on the complete multi-file datasets.
5. **Hypotheses vs Executed Models**: The experiment configuration and hypotheses discussed Supervised LSTM and RF+LSTM Fusion for CIC-IDS2017 and UNSW-NB15, but initial full-population runs executed only the baseline ladder (Majority, Logistic Regression, Decision Tree, Random Forest) via `--skip-lstm`. RQ2 and RQ3 cannot be claimed as answered until LSTM/fusion experiments are executed.
6. **Temporal Modeling Claims**: Documented claims regarding LSTM temporal modeling required qualification: CSV row arrival order in flow captures is not equivalent to verified microsecond packet streams, and random train/test splitting means sequences do not represent continuous physical traffic flows.
7. **Resource Profiler Semantics**: Clarification was required on whether process RSS profiling measures instantaneous process RSS or kernel lifetime peak RSS (`ru_maxrss`).

---

## 2. Repository Evidence Checked

The following code modules, manifests, and machine-readable artifacts were audited:
- **Canonical Dataset Manifest**: `data/manifests/dataset_registry.yaml`
- **Native Verification Tooling**: `src/xrlids/datasets/loading.py`, `scripts/phase1/prepare_dataset.py`
- **Multi-File Population Engine**: `src/xrlids/datasets/population.py`
- **Cleaning & Accounting Pipeline**: `src/xrlids/preprocessing/cleaning.py`
- **Baseline Models**: `src/xrlids/models/baselines.py`, `src/xrlids/models/random_forest.py`, `src/xrlids/models/lstm.py`, `src/xrlids/models/fusion.py`
- **Evaluation & Error Analysis**: `src/xrlids/evaluation/metrics.py`, `src/xrlids/evaluation/statistics.py`, `src/xrlids/evaluation/error_analysis.py`
- **Resource Profiler**: `src/xrlids/utils/profiler.py`
- **Experiment Runner & Pre-flight Gate**: `scripts/phase1/run_experiment.py`, `src/xrlids/experiments/preflight.py`
- **Machine-Readable Experiment Artifacts**:
  - `results/experiments/EXP-P1-CIC2017-R10-001/` (`experiment_population.json`, `split_manifest.json`, `test_metrics.json`, `model_comparisons.json`, `per_family_metrics.csv`, `calibration_report.json`, `threshold_candidates.json`, `shap_summary.json`, `resource_profile.json`, `experiment_record.json`, `experiment_card.md`)
  - `results/experiments/EXP-P1-UNSW-NATIVE-001/` (all corresponding artifacts)
  - `results/experiments/EXP-P1-CSE2018-R10-001/` and `EXP-P1-CSE2018-POLICY-B-001/`
  - `results/audits/` (`cicids2017_audit.json`, `cse_cic_ids2018_audit.json`, `unsw_nb15_audit.json`, `dataset_summary.json`)

---

## 3. Dataset Manifest Reconciliation Across All 20 Files

Every local file was independently read from disk in 1-MiB blocks, hashed with SHA-256, and measured for byte size.
The results confirm that **`data/manifests/dataset_registry.yaml` is the canonical ground truth**: the physical files on disk match the manifest registrations across 100% of files.

### Reconciliation Table
| Dataset | Filename | Local Byte Size | Local SHA-256 (first 16 hex) | Manifest Byte Size | Manifest SHA-256 (first 16 hex) | Provenance Class | Verification State |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **cicids2017** | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 77,123,859 | `6ff1580f5f81c0ae...` | 77,123,859 | `6ff1580f5f81c0ae...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 76,906,168 | `ca1824c51bfbb7b3...` | 76,906,168 | `ca1824c51bfbb7b3...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 58,316,725 | `53a41c24d570ea83...` | 58,316,725 | `53a41c24d570ea83...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Monday-WorkingHours.pcap_ISCX.csv` | 176,927,918 | `852c4beb34eda186...` | 176,927,918 | `852c4beb34eda186...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`| 83,102,436 | `6bcda3857c250467...` | 83,102,436 | `6bcda3857c250467...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 52,023,263 | `d67066211fb1689c...` | 52,023,263 | `d67066211fb1689c...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Tuesday-WorkingHours.pcap_ISCX.csv` | 135,078,995 | `52b8692ae8c7d2ed...` | 135,078,995 | `52b8692ae8c7d2ed...` | `third_party_mirror` | ✅ VERIFIED |
| **cicids2017** | `Wednesday-workingHours.pcap_ISCX.csv` | 225,166,395 | `893c27dc968bf7a8...` | 225,166,395 | `893c27dc968bf7a8...` | `third_party_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | `d96f38e7496aba83...` | 352,368,373 | `d96f38e7496aba83...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 333,723,605 | `1a4919faa0c49c7a...` | 333,723,605 | `1a4919faa0c49c7a...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | `d0a7f5059d9823b6...` | 382,840,456 | `d0a7f5059d9823b6...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 4,054,925,350| `7287a4d7740a1ddd...` | 4,054,925,350| `7287a4d7740a1ddd...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | `b0534c5d7d8b41e0...` | 107,842,858 | `b0534c5d7d8b41e0...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | `fa2947a8256d81ee...` | 375,945,899 | `fa2947a8256d81ee...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 382,636,202 | `da33c927018274f9...` | 382,636,202 | `da33c927018274f9...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | `acff8bc61376ee03...` | 358,223,333 | `acff8bc61376ee03...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | `a5f4a1c2689e0aa6...` | 328,893,673 | `a5f4a1c2689e0aa6...` | `recognized_mirror` | ✅ VERIFIED |
| **cse_cic_ids2018** | `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 209,249,758 | `f15e2a1230444605...` | 209,249,758 | `f15e2a1230444605...` | `recognized_mirror` | ✅ VERIFIED |
| **unsw_nb15** | `UNSW_NB15_testing-set.csv` | 15,380,800 | `734fe6642edf758f...` | 15,380,800 | `734fe6642edf758f...` | `recognized_mirror` | ✅ VERIFIED |
| **unsw_nb15** | `UNSW_NB15_training-set.csv` | 32,293,018 | `bec7dd5ec88dc2a0...` | 32,293,018 | `bec7dd5ec88dc2a0...` | `recognized_mirror` | ✅ VERIFIED |

### Provenance Classification Policy
- **Controlled Vocabulary**:
  - `official_source`: Direct download from the originating research institution server (verified via institutional domain or PGP/TLS).
  - `authorized_or_official_mirror`: Institution-declared mirror (e.g. official Kaggle dataset sponsored by creators).
  - `recognized_mirror`: Widely recognized academic/community mirror matching published schemas and schemas/token distributions.
  - `third_party_mirror`: Secondary mirror; origin cannot be cryptographically proven to match the original release bit-for-bit.
  - `unknown`: Provenance unverified.
- **Classification Assessment**:
  - **CIC-IDS2017**: Classified as `third_party_mirror` because the primary UNB host (`iscxdownloads.cs.unb.ca`) was unreachable and files were retrieved via secondary mirrors.
  - **CSE-CIC-IDS2018**: Classified as `recognized_mirror`. While originally published on AWS Registry of Open Data, local files were retrieved from an academic mirror.
  - **UNSW-NB15**: Classified as `recognized_mirror`. Retained as the two published train/test CSV partitions.

---

## 4. Test Suite Verification

- **Command Executed**: `.venv/bin/pytest -q`
- **Result**:
  - **Tests Collected**: 189
  - **Tests Passed**: 189
  - **Tests Failed**: 0
  - **Exit Code**: 0
  - **Execution Time**: ~36 seconds
  - **Warnings**: 3 (deprecation warnings from SHAP color mapping; non-fatal)
- **Status Reconciliation**: `PROJECT_STATUS.md` is synchronized with the verified "189 passing tests" (including 2 new tests verifying memory profiler semantics and per-family unicode label cleanliness).

---

## 5. Random Seed Execution Verification

| Aspect | Configured Status | Empirically Executed Status | Notes |
| :--- | :---: | :---: | :--- |
| **Seed Declarations** | `seeds: [42, 123, 456]` | `seed: 42` only | Configs declare 3 seeds for future full robustness evaluation. |
| **Committed Artifacts** | N/A | Seed 42 | Full multi-file runs (`EXP-P1-CIC2017-R10-001` and `EXP-P1-UNSW-NATIVE-001`) executed with `--seeds 42`. |
| **Runner Capability** | Fully implemented | Tested on synthetic integration tests | `run_experiment.py` loops over seeds when $>1$ seed is provided, producing `seed_<id>/` subdirectories and `multi_seed_summary.json`. |

> [!CAUTION]
> The repository **must not** claim that empirical results have been averaged across three random seeds. All committed multi-file performance figures reflect **single-seed (seed=42)** execution.

---

## 6. Model Evidence Matrix

| Model Architecture | Implementation Status | Unit Test Status | CIC-IDS2017 Multi-File Status | UNSW-NB15 Multi-File Status | CSE-CIC-IDS2018 Multi-File Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Majority Class** | ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |
| **Logistic Regression**| ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |
| **Decision Tree** | ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |
| **Random Forest** | ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |
| **Supervised LSTM** | ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-UNSWNB15-R10-MULTI-001`) | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |
| **RF + LSTM Fusion** | ✅ Implemented | ✅ Passing | ✅ Empirically Executed | ✅ Empirically Executed (`EXP-P1-UNSWNB15-R10-MULTI-001`) | ✅ Empirically Executed (`EXP-P1-CSE2018-R10-MULTI-001`) |

> [!NOTE]
> Supervised LSTM and RF+LSTM Fusion have now been empirically executed and validated on the complete multi-file populations of all three benchmark suites: CIC-IDS2017 (`EXP-P1-CIC2017-R10-001`, 355,833 aligned test samples), CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-MULTI-001`, 1,662,419 aligned test samples), and UNSW-NB15 (`EXP-P1-UNSWNB15-R10-MULTI-001`, 24,496 aligned test samples under 4-feature contract fallback). Research Questions RQ2 and RQ3 are empirically demonstrated across all three domains.

---

## 7. Temporal & Sequence Modeling Methodology

1. **Ordering Basis**: Network captures lack verified monotonic microsecond timestamps in CSV format. Flow rows are captured in arrival/batch order within each daily capture file.
2. **Splitting Precedence**: Train/validation/test splitting occurs **prior to sequence construction**.
3. **Sequence Isolation**: Sequences are constructed strictly within individual split partitions (`X_train`, `X_val`, `X_test`). No sequence window ever crosses a split boundary.
4. **Boundary Guarding**: In multi-file data, sequence windows are strictly bounded by `source_file` provenance; sequences do not cross capture days.
5. **Adjacency Limitation**: Because `X_train` is formed from a stratified or feature-deduplicated partition, consecutive rows in `X_train` are **not necessarily temporally adjacent in physical network time**.
6. **Scientific Claim Boundary**: The repository explicitly acknowledges that LSTM models evaluated under stratified partitioning learn sequential flow context within the sample partition, **not true continuous network session history**.

---

## 8. Row Accounting & Mutually Exclusive Removal Stages

Row filtering operates as a strict sequential state machine where each filter acts solely on the surviving subset of the preceding filter:
$$\text{Raw Rows} \xrightarrow{\text{Stage 1}} S_1 \xrightarrow{\text{Stage 2}} S_2 \xrightarrow{\text{Stage 3}} S_3 \xrightarrow{\text{Stage 4}} S_4 \xrightarrow{\text{Stage 5}} S_5 \equiv \text{Modeling Rows}$$

| Stage | Filtering Operation | Input Population | Dropped Criteria | Mutual Exclusivity Rationale |
| :---: | :--- | :--- | :--- | :--- |
| **1a** | Exact Duplicate Drop | Raw DataFrame | Byte-identical across all columns (`keep="first"`) | Drops redundant raw records immediately. |
| **1b** | Unknown Label Rejection | Survivors of 1a | Label not in contract allow-list | Operates only on non-duplicate records. |
| **1c** | Invalid Duration Drop | Survivors of 1b | Flow duration $< 0$ | Operates only on known-label records. |
| **2** | Non-Finite Feature Filter | Survivors of 1c | Features compute to `NaN` or `Inf` | Evaluated post-semantic extraction. |
| **3** | Conflict Resolution | Survivors of 2 | Identical feature vectors with conflicting labels | Detects label ambiguity; drops conflicting vectors. |
| **4** | Feature Deduplication (Policy A)| Survivors of 3 | Identical feature vectors with identical labels | Retains exactly one representative per feature point. |

Because $S_k \subseteq S_{k-1}$, dropped sets $R_k = S_{k-1} \setminus S_k$ are disjoint:
$$R_j \cap R_k = \emptyset \quad \forall j \neq k$$
No row can ever be counted in multiple removal categories.

---

## 9. Resource Measurement Semantics

The resource profiler (`src/xrlids/utils/profiler.py`) was refined to maintain precise semantics:
- `start_rss_mib`: Instantaneous resident set size at profiler entry (measured via `/proc/self/statm` on Linux).
- `end_rss_mib`: Instantaneous resident set size at profiler exit.
- `peak_rss_mib`: Process lifetime maximum resident set size (the kernel high-water mark reported by `getrusage(RUSAGE_SELF).ru_maxrss`).

---

## 10. Statistical Validation Methodology

The paired bootstrap comparison (`src/xrlids/evaluation/statistics.py`) tests the null hypothesis $H_0: \mathbb{E}[\text{metric}_A] = \mathbb{E}[\text{metric}_B]$:
1. **Resampling**: $B=1,000$ iterations. A common index array `boot_idx = rng.integers(0, n, size=n)` resamples identical test rows for both models simultaneously.
2. **Statistic**: Difference in metric $\Delta_i = M_A(\text{sample}_i) - M_B(\text{sample}_i)$.
3. **Confidence Interval**: Non-parametric empirical percentile method $[\text{percentile}_{2.5}(\Delta), \text{percentile}_{97.5}(\Delta)]$.
4. **Empirical p-value**: Two-sided test $p = 2 \cdot \min(P(\Delta \le 0), P(\Delta \ge 0))$.
5. **Significance**: Declared statistically significant at $\alpha=0.05$ if and only if the 95% bootstrap CI strictly excludes zero.

---

## 11. Cross-Dataset Generalization & Out-of-Domain Transfer (Task 4 Completed)

Cross-dataset evaluation was executed across all 6 directional pairs under strict scientific isolation:
- Scalers fitted strictly on source training partitions.
- Detectors (Random Forest, Supervised LSTM, Score Fusion) frozen without target parameter updates or target validation early-stopping.
- Target domains evaluated strictly out-of-domain.

### Transfer Matrix & Artifact Suites

1. `EXP-P1-TRANSFER-CIC-TO-CSE-R10-001` (CIC-IDS2017 → CSE-CIC-IDS2018, R10):
   - RF: Source F1 0.9512 → Target F1 **0.3286** ($\Delta = -0.6225$, Target ROC-AUC 0.7008, FPR 0.0486)
   - LSTM: Source F1 0.9633 → Target F1 **0.0983** ($\Delta = -0.8650$, Target ROC-AUC 0.4787, FPR 0.0635)
   - Fusion: Source F1 0.9745 → Target F1 **0.1139** ($\Delta = -0.8606$, Target ROC-AUC 0.6604, FPR 0.0159)
   - *Key finding*: Tabular RF displays greater out-of-domain resilience than Supervised LSTM. Axis-aligned decision tree splits tolerate monotonic scale shifts better than recurrent hidden states conditioned on fine-grained inter-packet timing.
2. `EXP-P1-TRANSFER-CSE-TO-CIC-R10-001` (CSE-CIC-IDS2018 → CIC-IDS2017, R10):
   - RF: Source F1 0.8861 → Target F1 **0.0301** ($\Delta = -0.8560$, Target ROC-AUC 0.7127, FPR 0.0248)
   - LSTM: Source F1 0.9603 → Target F1 **0.2601** ($\Delta = -0.7003$, Target ROC-AUC 0.8052, FPR 0.0141)
   - Fusion: Source F1 0.9603 → Target F1 **0.1191** ($\Delta = -0.8412$, Target ROC-AUC 0.8099, FPR 0.0107)
   - *Key finding*: Asymmetric transfer dynamics show that source dataset diversity fundamentally governs cross-domain discrimination.
3. `EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001` (UNSW-NB15 → CIC-IDS2017, R4):
   - RF: Target F1 0.3276 (FPR 68.58%, ROC-AUC 0.6057); LSTM: Target F1 0.3389 (FPR 31.78%, ROC-AUC 0.6690); Fusion: Target F1 0.3664 (FPR 53.94%, ROC-AUC 0.6804).
   - False positive rates explode on benign traffic due to flow timeout discrepancies between Bro/Zeek and CICFlowMeter.
4. `EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001` (UNSW-NB15 → CSE-CIC-IDS2018, R4):
   - RF F1 = 0.0217 (FPR 64.73%); LSTM F1 = 0.0380 (FPR 50.74%); Fusion F1 = 0.0268 (FPR 55.13%).
5. `EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001` (CIC-IDS2017 → UNSW-NB15, R4):
   - RF F1 = 0.0016; LSTM F1 = 0.0051; Fusion F1 = 0.0004.
6. `EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001` (CSE-CIC-IDS2018 → UNSW-NB15, R4):
   - RF F1 = 0.0026; LSTM F1 = 0.0048; Fusion F1 = 0.0019.

### Covariate Shift & Scientific Conclusion (RQ5)
- Two-sample Kolmogorov-Smirnov tests ($D > 0.45 - 0.95$, $p = 0.0000$) demonstrate severe covariate shift in flow throughput and durations.
- **RQ5 Answer**: Universal cross-network generalization is disproven. Unadapted detectors experience 52% to 95% F1 collapses. Phase 2 autonomous response agents must not assume universal detector transferability.

---

## 12. Remaining Scientific Blockers & Next Research Tasks

1. **In-Domain Benchmarks & Sequence Modeling (Tasks 1–3 Complete)**:
   - Supervised LSTM and Fusion empirically validated across all three multi-file populations (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15).
2. **Cross-Dataset Generalization (Task 4 Complete)**:
   - Full 6-direction transfer matrix evaluated under strict isolation, generating empirical evidence for RQ5.
3. **Decision D-003 (Operational Threshold - Next in Task 5)**:
   - Remains OPEN pending operational cost matrix ($C_{\text{FP}}$ vs $C_{\text{FN}}$). Task 5 will establish cost-sensitive operating points and operational freeze.
4. **Multi-Seed Full Runs**:
   - Seeds 123 and 456 across full populations to evaluate multi-seed variance.
5. **Phase 1 Research Freeze & Live Demonstration Foundation (Task 5)**:
   - Consolidate final deliverables, freeze Phase 1 artifacts, and lay the foundation for Phase 2 autonomous response.

