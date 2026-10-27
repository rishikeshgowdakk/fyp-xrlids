# XRL-IDARS — Forensic Audit Checklist

**Document Identifier**: `CHECKLIST-P2-AUDIT-001`  
**Reference Document**: [`docs/audits/XRL_IDARS_FORENSIC_AUDIT.md`](XRL_IDARS_FORENSIC_AUDIT.md)  
**Status**: AUDITED & COMPLETED (All 419 Test Suite Verified)  
**Date**: October 28, 2026  

---

## 1. Perception & Detection Models

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Random Forest Baseline** | Trainable, reproducible, test F1 $\ge 0.88$ | **PASS** | [`src/xrlids/models/random_forest.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/random_forest.py); `test_metrics.json` | F1 = 0.9512 (CIC-2017), 0.8861 (CSE-2018), 0.8548 (UNSW-NB15). |
| **Supervised LSTM Model** | Sequence length $T=5$, valid forward pass, reproducible checkpoints | **PASS** | [`src/xrlids/models/lstm.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/lstm.py); `lstm.pt` | Checkpoint verified. Model functions as a non-linear tabular aggregator. |
| **LSTM Physical Chronology** | Sequences capture true physical packet arrival timelines | **FAIL** | [`scripts/phase1/run_lstm_temporal_ablation.py`](file:///home/rishikesh/Desktop/fyp-xrlids/scripts/phase1/run_lstm_temporal_ablation.py) | Sequences built across CSV file order. Shuffled ablation ($\Delta F_1 = -0.0038$) proves chronology is unproven. |
| **Score Fusion Formula** | $S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1 - \alpha) \cdot S_{\text{LSTM}}$ correctly implemented | **PASS** | [`src/xrlids/models/fusion.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/fusion.py) | Mathematical formulation and population alignment strictly verified. |
| **Fusion Superiority (All Domains)** | Score fusion outperforms both constituent models on all datasets | **PARTIAL** | `test_metrics.json` across 3 benchmarks | **PASS** on CIC ($\Delta F_1 = +0.023$) and UNSW ($\Delta F_1 = +0.042$). **FAIL** on CSE-2018 ($\alpha = 0.00$, pure LSTM selected). |
| **Calibrated Probability Fusion** | Blended scores represent calibrated class probabilities | **FAIL** | [`src/xrlids/models/fusion.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/fusion.py) | Linear blend combines raw RF tree votes and uncalibrated LSTM sigmoids. |
| **Production Integration of Fusion** | Fusion model evaluated in real-time in the live monitor | **FAIL** | [`dashboard/server.py`](file:///home/rishikesh/Desktop/fyp-xrlids/dashboard/server.py) | Live monitor runs tabular RF only; LSTM and Fusion are offline research artifacts. |

---

## 2. Feature Contracts & Live Parity

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Canonical R10 Contract** | 10 portable transport/statistical features defined and validated | **PASS** | [`src/xrlids/features/definitions.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/features/definitions.py) | Features exclude IP addresses, MAC addresses, and socket ports to prevent leakage. |
| **Live Extraction Parity** | Live flow extractor matches dataset features within $\text{atol} \le 10^{-4}$ | **PASS** | `tests/integration/test_feature_parity.py` | Verified across synthetic streams and PCAP replay. |
| **Train-Only Preprocessing** | Scalers and normalizers fitted strictly on $X_{\text{train}}$ | **PASS** | [`src/xrlids/preprocessing/pipeline.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/preprocessing/pipeline.py) | Zero test-set statistics leak into preprocessing pipelines. |
| **Degraded Sensor Schema Handling** | Programmatic fallback to R4 contract when transport flags are missing | **PASS** | [`src/xrlids/experiments/transfer.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/experiments/transfer.py) | Correctly quarantines UNSW-NB15 under 4-feature contract without data fabrication. |

---

## 3. Data Leakage & Splitting Integrity

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Exact Cross-Split Vector Leakage (L-01/L-02)** | Zero shared feature vectors between train, validation, and test splits | **PASS** | [`src/xrlids/splitting/leakage.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/splitting/leakage.py) | Policy A feature deduplication guarantees disjointness. |
| **Sequence Overlap Across Splits (L-06)** | Sequences do not cross split boundaries | **PASS** | [`src/xrlids/models/lstm.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/lstm.py) | Verified by construction; sequences generated within individual split slices. |
| **Ambiguous Vector Representation** | All network traffic is cleanly separable by the 10-feature vector | **FAIL** | [`scripts/phase1/evaluate_ambiguous_traffic.py`](file:///home/rishikesh/Desktop/fyp-xrlids/scripts/phase1/evaluate_ambiguous_traffic.py) | 27.7% of CSE-2018 flows have conflicting labels. Bayes ceiling on this region is ~64.3%. |
| **Future-Day Generalization** | Models maintain high accuracy under strict temporal holdout | **FAIL** | [`reports/generated/temporal_split_report.md`](file:///home/rishikesh/Desktop/fyp-xrlids/reports/generated/temporal_split_report.md) | RF $F_1$ collapses from 0.8861 to **0.0113** due to unseen attack families and novelty selection. |
| **Cross-Dataset Zero-Shot Transfer** | Models generalize zero-shot across disparate network environments | **FAIL** | `reports/generated/transfer_report.md` | $F_1$ drops by 52% to 95% across all 6 transfer directions. |

---

## 4. Explainability (TreeSHAP)

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Additive Efficiency Check** | $\sum \phi_i + \text{base\_value} = f(x)$ holds exactly | **PASS** | [`src/xrlids/explainability/shap_analysis.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/explainability/shap_analysis.py) | Verified mathematically across test instances. |
| **Correct Model Attribution** | SHAP explains the active detector producing predictions | **PASS** | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` | Accurately explains tabular Random Forest predictions. |
| **SHAP Scope Transparency** | TreeSHAP explains only the RF, not the LSTM or Fusion | **PASS** | [`docs/final/VIVA_DEFENSE_AND_METHODOLOGY_REPORT.md`](file:///home/rishikesh/Desktop/fyp-xrlids/docs/final/VIVA_DEFENSE_AND_METHODOLOGY_REPORT.md) | Scope boundary is clearly documented in research reports. |

---

## 5. Autonomous Response (DQN Architecture & Training)

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Dueling DQN Implementation** | Value $V(s)$ and Advantage $A(s, a)$ stream separation | **PASS** | [`src/xrlids/response/dqn/network.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/dqn/network.py) | Architecture matches specifications and loads cleanly. |
| **6D Causal State Vector** | Zero target leakage, normalized bounded dimensions | **PASS** | [`src/xrlids/response/state.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/state.py) | Target labels $y$ strictly excluded from observation vector $s_t$. |
| **Prioritized Experience Replay** | Proportional priority sampling with $\beta$-annealing | **PASS** | [`src/xrlids/response/dqn/replay.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/dqn/replay.py) | Verified unit tests confirm sampling and weight updates. |
| **Sequential Transition Dynamics** | Environment exhibits multi-step packet/flow state transitions | **FAIL** | [`src/xrlids/response/environment.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/environment.py) | Flows arrive from exogenous pre-recorded trace; environment is a Contextual Bandit. |
| **Sensor Jitter Stability (RQ7.2)** | Action Chattering Index $\text{ACI} < 0.05$ under score noise $\sigma \le 0.20$ | **FAIL** | `score_jitter_robustness.json` | $\text{ACI} \approx 0.11 > 0.05$. Policy chatters under score noise. |
| **Stealth Attack Containment** | Graded escalation contains low-footprint attack campaigns | **PARTIAL** | `stealth_campaign_results.json` | Contained Web Brute Force and XSS; **failed** on Infiltration and SQLi (0% isolation). |

---

## 6. Research Hypotheses & Statistical Baselines

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Statistical Cost Reduction ($H_0$ Rejected)** | Paired bootstrap reduction over Baseline 2 with $p < 0.01$ | **PASS** | [`results/phase2/EXP-P2-FINAL-TEST-001/final_test_bootstrap.json`](file:///home/rishikesh/Desktop/fyp-xrlids/results/phase2/EXP-P2-FINAL-TEST-001/final_test_bootstrap.json) | $p < 0.001$ across Balanced, Aggressive, and Conservative regimes. |
| **Pre-Registered Practical Criterion** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction over best baseline | **FAIL** | `final_test_bootstrap.json` | Achieved **+11.29%** (Balanced), **+14.10%** (Aggressive), **+2.05%** (Conservative). Target **NOT MET**. |
| **4-Action Stability (RQ7.1)** | Action Chattering Index $\text{ACI} < 0.01$ in 4-action mode | **FAIL** | `final_test_metrics.json` | 3-action passed ($\text{ACI} = 0.0019$); 4-action failed ($\text{ACI} = 0.0214$). |
| **Out-of-Domain Transfer Safety (RQ7.2)** | False Quarantine Rate $\text{FQR} < 2.0\%$ under domain shift | **PASS** | `transfer_safety_results.json` | $\text{FQR} = 0.51\%$, Business Availability = 97.69% on CSE-CIC-IDS2018. |

---

## 7. Safety Invariants & Rollback Harness

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Critical Host Exemption** | Gate intercepts and downgrades isolations on critical infrastructure | **PASS** | [`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py) | 100% of invalid isolations on gateway/DNS safely downgraded to `ALERT`. |
| **Mandatory Action Cooldown** | Prevents de-escalation oscillation within 30-step window | **PASS** | [`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py) | Evaluated and verified across baseline and DQN runs. |
| **Blast Radius Circuit Breaker** | Capped at maximum 5.0% isolated endpoint population | **PASS** | [`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py) | Hard ceiling enforced in simulator and lab actuator. |
| **Atomic Response Transaction Rollback** | Cryptographic state snapshot, watchdog TTL, and verified rollback | **PASS** | [`src/xrlids/response/transaction.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/transaction.py); `EXP-P3G-ROLLBACK-001` | 100/100 rollback stress transactions passed with zero host mutations. |
| **Zero Host Network Mutation** | Execution restricted to virtual netns (`10.200.1.0/24`) | **PASS** | [`src/xrlids/enforcement/lab.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/enforcement/lab.py) | Cryptographic baseline comparison proves `pre == post` SHA-256. |

---

## 8. Production & Deployment Readiness

| Audit Item / Claim | Tested Criteria | Status | Supporting Evidence / Location | Notes & Limitations |
| :--- | :--- | :---: | :--- | :--- |
| **Offline Academic Demonstration** | Standalone demo runs cleanly out-of-the-box without network mutation | **PASS** | [`scripts/demo/run_replay_demo.py`](file:///home/rishikesh/Desktop/fyp-xrlids/scripts/demo/run_replay_demo.py) | PCAP replay and JSON artifact generation verified. |
| **Dashboard Security & CSRF Hardening** | Origin/Host validation, path traversal guards on PCAP loading | **PASS** | [`dashboard/server.py`](file:///home/rishikesh/Desktop/fyp-xrlids/dashboard/server.py) | Hardened against cross-origin POST and arbitrary file path injection. |
| **Unrestricted Enterprise Autonomous Deployment** | Model safe to run without human supervision on production networks | **FAIL** | [`docs/audits/XRL_IDARS_FORENSIC_AUDIT.md`](XRL_IDARS_FORENSIC_AUDIT.md) | **NOT VALIDATED**. Default recommendation is strictly **Alert-Only / Advisory Mode**. |
