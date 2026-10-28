# XRL-IDARS — Phase 2B Forensic Readiness Audit: Model Integrity, Reproducibility, Evaluation Correctness, and Production-Gap Assessment

- **Audit Identifier**: `EXP-P2B-READINESS-AUDIT-CLOSURE-001`
- **Git Commit (HEAD)**: `f15be7e78fb1abfa545a65d4ff832ecd602bf461` (Branch: `main`)
- **Code Revision Tested**: `f15be7e78fb1abfa545a65d4ff832ecd602bf461+dirty`
- **Audit Execution Timestamp**: `2026-10-28T13:55:10.786973+00:00`
- **Auditor Role**: Senior ML Systems Engineer, Model Validation Engineer, & Independent Research Auditor
- **Working Tree Status**: DIRTY / UNCOMMITTED (4 modified tracked files: M README.md, M reports/generated/phase1_final_report.md, M reports/generated/phase1_status.md, M scripts/phase2/run_phase2b_readiness_audit.py)

---

## 1. Executive Summary

This forensic readiness audit independently investigated the entire XRL-IDARS repository across model binaries, feature contracts, evaluation pipelines, mathematical derivations, statistical testing, and documentation consistency.

### Key Audit Conclusions:
1. **Model Binary Integrity (100% Verified)**:
   - All **9 canonical model binaries** (`models/rf/`, `models/lstm/`, `models/dqn/`, `models/fusion/`) are **physically committed and tracked directly in the git repository**.
   - **100% cryptographic match**: Every binary's SHA-256 hash and byte size matches `models/registry/model_manifest.json` and `models/registry/registry.yaml` exactly.
   - No Git LFS or external artifact retrieval mechanism is required to load models.
2. **Population Reconciliation Resolved (355,865 vs 355,833)**:
   - The 32-flow discrepancy between the Phase 2 tabular evaluation count (**355,865**) and the Phase 1 sequence-aligned count (**355,833**) is **mathematically proven and legitimate**:
     $$\text{Aligned Flows} = 355,865 - (8 \text{ capture files} \times 4 \text{ boundary flows dropped for } T=5) = 355,833$$
   - Tabular evaluations (RF and Phase 2 flow replay) evaluate the full unconstrained 355,865 flows, while sequence models (LSTM and Fusion) drop the first 4 flows of each file to avoid crossing capture boundaries.
3. **DQN Value Assessment: Empirically Refuted**:
   - In the controlled benchmark on the 355,865 held-out test flows, the zero-parameter analytic `CostOptimalThresholdPolicy` achieves **lower operational cost than the trained DQN in 4 out of 6 experimental settings**.
   - In 4-action High Availability, Cost-Optimal beats DQN by **20.12%** ($1,547,511.0$ vs $1,937,476.5$).
   - In the remaining 2 settings, DQN's advantage is only **8.8%**, failing the pre-registered 15.0% target.
4. **Causal Reality of the Environment**:
   - The simulation environment is an **Asymmetric-Loss Contextual Bandit with Hysteresis Constraints**, NOT a sequential Markov Decision Process. Network flow arrivals are purely exogenous replay.
5. **Documentation Contradictions Identified & Resolved**:
   - `README.md` lines 188-200 contained outdated text claiming model artifacts were uncommitted. Reconciled: model binaries are committed; raw CSV datasets remain external.
   - `README.md` test count stated 417/459 tests. Reconciled: the test suite now collects and passes **466 tests** (372 unit, 45 data, 31 integration, 18 model).

---

## 2. Canonical Model Artifact Integrity Matrix

| Model ID | Type | Dataset | Contract | Size (Bytes) | SHA-256 Hash | Registry Status | Inference Status |
|:---|:---:|:---:|:---:|---:|:---|:---:|:---:|
| `random_forest_cicids2017.joblib` | `rf` | `cicids2017` | `R10` | 26,363,055 | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` | `VERIFIED_MATCH` | `PASS` |
| `random_forest_cse2018.joblib` | `rf` | `cse_cic_ids2018` | `R10` | 68,240,031 | `b7d2dc7bacca1a46f4da35aee2c19e1604020d429a5d29b72d742130215ba9b3` | `VERIFIED_MATCH` | `PASS` |
| `random_forest_unswnb15.joblib` | `rf` | `unsw_nb15` | `R4` | 22,639,151 | `c432eb067507ad5b29a542b372ac6d35e609e783a9e6094c9764d0cfe654ec7c` | `VERIFIED_MATCH` | `PASS` |
| `lstm_cicids2017.pt` | `lstm` | `cicids2017` | `R10` | 60,437 | `18b0bfb48d3b031c17b26d3abd12485e09f8dd8c330fad26858320f11f818be1` | `VERIFIED_MATCH` | `PASS` |
| `lstm_cse2018.pt` | `lstm` | `cse_cic_ids2018` | `R10` | 60,949 | `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a` | `VERIFIED_MATCH` | `PASS` |
| `lstm_unswnb15.pt` | `lstm` | `unsw_nb15` | `R4` | 57,813 | `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd` | `VERIFIED_MATCH` | `PASS` |
| `dqn_4action_best.pt` | `dqn` | `cicids2017` | `response_state_v1` | 43,189 | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` | `VERIFIED_MATCH` | `PASS` |
| `dqn_3action_best.pt` | `dqn` | `cicids2017` | `response_state_v1` | 42,997 | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` | `VERIFIED_MATCH` | `PASS` |
| `fusion_weights.json` | `fusion` | `None` | `None` | 1,005 | `fd50a413119d3ec3b0c7515125cf6e0f4a605aa52ca2739b9fcd951f8e081c72` | `VERIFIED_MATCH` | `PASS` |

---

## 3. Population Reconciliation Table (Exact Per-File Recomputation)

| Evaluation Population Scope | Total Flows | Benign Flows | Attack Flows | Attack % | Dropped Boundary Flows | Feature Contract |
|:---|---:|---:|---:|---:|---:|:---:|
| **Tabular Test Split (Phase 2 & RF)** | **355,865** | 291,045 | 64,820 | 18.2148% | 0 | Tabular R10 |
| **Sequence-Aligned Test Slice (LSTM & Fusion)** | **355,833** | 291,013 | 64,820 | 18.2164% | 32 (8 files × 4) | Sequence $T=5$ |

### Exact Per-Capture-File Breakdown Across All 8 CIC-IDS2017 Files

| Capture File Name | Before Filtering (Tot / Ben / Atk) | After Filtering (Tot / Ben / Atk) | Dropped Boundary Flows (Tot / Ben / Atk) |
|:---|---:|---:|---:|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 41,768 / 16,421 / 25,347 | 41,764 / 16,417 / 25,347 | 4 / 4 / 0 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 18,892 / 18,572 / 320 | 18,888 / 18,568 / 320 | 4 / 4 / 0 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 26,961 / 26,765 / 196 | 26,957 / 26,761 / 196 | 4 / 4 / 0 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 69,273 / 69,273 / 0 | 69,269 / 69,269 / 0 | 4 / 4 / 0 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 28,715 / 28,707 / 8 | 28,711 / 28,703 / 8 | 4 / 4 / 0 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 21,683 / 21,314 / 369 | 21,679 / 21,310 / 369 | 4 / 4 / 0 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 56,624 / 55,079 / 1,545 | 56,620 / 55,075 / 1,545 | 4 / 4 / 0 |
| `Wednesday-workingHours.pcap_ISCX.csv` | 91,949 / 54,914 / 37,035 | 91,945 / 54,910 / 37,035 | 4 / 4 / 0 |
| **TOTAL SUMMARY** | **355,865 / 291,045 / 64,820** | **355,833 / 291,013 / 64,820** | **32 / 32 / 0** |

> [!NOTE]
> **Exact Mathematical Derivation**: 355,865 tabular test flows - (8 capture files * 4 dropped boundary flows) = 355,833 flows. For sequence length T = 5, constructing causal sequences strictly within each capture file requires dropping the first (T - 1) = 4 flows of each file so sequences never cross unrelated files. Across the 8 CIC-IDS2017 capture files, exactly 8 * 4 = 32 boundary flows are excluded for sequence models. Every single one of the 32 dropped boundary flows was a benign baseline flow (zero attack flows dropped). Tabular detectors (Random Forest and Phase 2 offline flow replay) consume per-flow tabular features and therefore evaluate the complete, unconstrained 355,865 test population.

---

## 4. Latency and Computational Throughput Reconciliation

| Execution Component | Batch Size | Hardware / Execution Mode | Median Latency | p95 Latency | Throughput |
|:---|:---:|:---|---:|---:|---:|
| `Baseline_4_Cost_Optimal` Policy-Only | 1 | Python CPU (Single Flow) | **1.95 µs** | 2.35 µs | 491,112 flows/s |
| `DQN_Candidate_4action` Policy-Only | 1 | PyTorch CPU (Single Flow) | **100.23 µs** | 116.09 µs | 9,063 flows/s |
| `StateBuilder` + `DeterministicSafetyGate` | 1 | Python CPU | **43.31 µs** | 45.20 µs | 23,089 flows/s |
| Full Simulation E2E (Cost-Optimal) | 1 | Python CPU | **45.26 µs** | 49.12 µs | 20,333 flows/s |
| Full Simulation E2E (DQN) | 1 | Python + PyTorch CPU | **159.68 µs** | 182.40 µs | 5,705 flows/s |
| RF Detector Scoring (`n_jobs=1`) | 1 | scikit-learn CPU (200 trees) | **3,525 µs (3.5 ms)** | 3,712 µs | 284 flows/s |
| RF Detector Scoring (`n_jobs=4`) | 1 | joblib multiprocessing overhead | **23,868 µs (23.9 ms)** | 25,745 µs | 42 flows/s |
| RF Detector Scoring (Batched) | 100 | scikit-learn CPU | **53.87 µs/flow** | 62.10 µs | 18,563 flows/s |

---

## 5. Safety Invariant & Failure Mode Audit

| Safety Test Case | Invariant Description | Expected Action | Observed Action | Overridden | Test Result |
|:---|:---|:---:|:---:|:---:|:---:|
| `critical_host_gateway_isolation_attempt` | Tested non-bypassable invariant | `ALERT` | `ALERT` | `True` | `PASS` |
| `3_action_clamp_isolate_to_rate_limit` | Tested non-bypassable invariant | `RATE_LIMIT` | `RATE_LIMIT` | `True` | `PASS` |
| `mandatory_cooldown_deescalation_thrash_block` | Tested non-bypassable invariant | `RATE_LIMIT` | `RATE_LIMIT` | `True` | `PASS` |
| `blast_radius_circuit_breaker_isolation_cap` | Tested non-bypassable invariant | `ALERT` | `ALERT` | `True` | `PASS` |
| `cost_optimal_nan_score_rejection` | Tested non-bypassable invariant | `ValueError` | `ValueError` | `N/A` | `PASS` |
| `cost_optimal_inf_score_rejection` | Tested non-bypassable invariant | `ValueError` | `ValueError` | `N/A` | `PASS` |

---

## 6. Prioritized Forensic Findings Ranked by Severity

### [CRITICAL] FINDING-P2B-001: Response Simulation Environment Is an Asymmetric Contextual Bandit, Not a Sequential MDP
- **Category**: `Scientific Integrity / Reinforcement Learning Justification`
- **Description**: Tracing of src/xrlids/response/environment.py demonstrates that network flow arrivals are strictly exogenous replay from pre-recorded datasets. Agent actions have zero causal influence over future traffic arrivals, packet timing, detector scores, or adversary behavior. Setting discount factor gamma = 0.95 optimizes noise correlations over 20 steps of exogenous traffic rather than genuine environmental transitions.
- **Evidence**: `src/xrlids/response/environment.py:204 next_flow = self.flows[self._current_step]`
- **Required Remediation**: Re-frame response architecture as an Asymmetric-Loss Contextual Decision Policy.

### [CRITICAL] FINDING-P2B-002: DQN Fails to Outperform Zero-Parameter Analytic Baseline in 4 of 6 Benchmark Settings
- **Category**: `Empirical Claim Validity`
- **Description**: In EXP-P2A-COST-OPTIMAL-001 on the 355,865 held-out test flows, the zero-parameter analytic CostOptimalThresholdPolicy achieved lower operational cost than the trained DQN in 4 out of 6 settings. In 4-action High Availability, Cost-Optimal beat DQN by 20.12%. In the 2 settings where DQN achieved lower cost, its advantage was only ~8.8%, failing the pre-registered 15.0% practical significance target.
- **Evidence**: `results/phase2/EXP-P2A-COST-OPTIMAL-001/baseline_results.json`
- **Required Remediation**: Honestly report negative findings regarding DQN superiority; do not claim DQN advantage over optimal baselines.

### [HIGH] FINDING-P2B-003: README.md Outdated Disclaimer Regarding Missing Model Artifacts
- **Category**: `Documentation Inconsistency`
- **Description**: README.md lines 188-200 claimed 'Artifacts and raw data are not committed... A fresh clone therefore contains no trained detector'. However, commit 29d8c1f explicitly unignored and tracked all 9 canonical model binaries and preprocessors directly in git. A clean checkout has all models immediately available.
- **Evidence**: `README.md:188-200 vs models/registry/model_manifest.json and clean worktree test`
- **Required Remediation**: Update README.md to state that canonical models ARE committed, while raw CSV datasets remain external.

### [HIGH] FINDING-P2B-004: README.md Test Suite Count Reconciled (417 vs 466 Executed Tests)
- **Category**: `Documentation Inconsistency`
- **Description**: README.md lines previously stated 'All 417 tests should pass'. Following the addition of Phase 2A/2B response and CSV workflow regression tests, the repository test suite consists of exactly 466 tests across tests/data/ (45), tests/integration/ (31), tests/model/ (18), and tests/unit/ (372), all 466 of which execute and pass in ~48s.
- **Evidence**: `pytest executes and passes 466 tests with 0 failures`
- **Required Remediation**: Update README.md test count to reflect the authoritative 466 executed and passed tests.

### [HIGH] FINDING-P2B-005: Reporting of p_value = 0.0 in Bootstrap Output
- **Category**: `Statistical Reporting`
- **Description**: Exported JSON files report p_value: 0.0 when 0 of 1,000 bootstrap resamples cross zero. In finite Monte Carlo resampling, the empirical resolution is bounded by p < 1/(B+1) = 0.000999 < 0.001. Claiming exact zero is statistically improper.
- **Evidence**: `results/phase2/EXP-P2A-COST-OPTIMAL-001/paired_comparisons.json`
- **Required Remediation**: Bound empirical bootstrap p-values by p < 1/(B+1) in documentation and schema.

### [MEDIUM] FINDING-P2B-006: Raw Random Forest Voting Scores Exhibit Severe Intermediate Probability Distortion
- **Category**: `Model Calibration`
- **Description**: Calibration report indicates that in [0.1, 0.2), mean predicted score is 0.1335 vs observed frequency 0.0137 (~10x gap). Analytical thresholds derived assuming S_t = P(y=1|x) are cost-optimal with respect to the assumed score, not proven Bayes-optimal.
- **Evidence**: `results/experiments/EXP-P1-CIC2017-R10-001/calibration_report.json`
- **Required Remediation**: Preserve explicit disclaimer in CostOptimalThresholdPolicy docstrings and reports.

### [MEDIUM] FINDING-P2B-007: CSE-CIC-IDS2018 Fusion Weight alpha = 0.00 (LSTM-Only Result)
- **Category**: `Benchmark Architecture`
- **Description**: In models/fusion/fusion_weights.json, CSE-2018 has alpha = 0.00. The fusion model contributes 0% Random Forest and 100% LSTM. Describing this as fusion outperforming individual models is misleading.
- **Evidence**: `models/fusion/fusion_weights.json`
- **Required Remediation**: Explicitly document that CSE-2018 fusion is mathematically identical to the single LSTM detector.

---

## 7. Scope-by-Scope Official Scientific Go / No-Go Decision

| Operational / Research Scope | Official Recommendation | Evidence & Scientific Rationale |
|:---|:---:|:---|
| **Academic Research Prototype** | **GO** | The codebase demonstrates clean modularity, rigorous feature contracts (R10/R4), non-bypassable safety gates, and excellent reproducibility. |
| **Reproducible Research Evaluation** | **GO** | All 9 canonical models, preprocessors, test splits, and benchmark scripts execute reproducibly from a clean checkout. |
| **Controlled Isolated-Lab Demonstration** | **GO** | The dashboard, PCAP replay, synthetic attack simulator, and namespace-isolated enforcement execute safely without host contamination. |
| **Live Observational Network Monitoring** | **GO** | The live packet extractor (`runner.py`) operates in read-only observation mode (`CAP_NET_RAW`), generating alerts without modifying firewall or routing rules. |
| **Autonomous Response in a Production Network** | **NO-GO** | Raw Random Forest scores exhibit severe intermediate probability distortion (~10× overconfidence), and the DQN fails to beat zero-parameter threshold rules. Autonomous isolation on real infrastructure would cause catastrophic false outages. |