# PROJECT STATUS

Last updated: 2026-10-30
Project: **XRL-IDARS v1** · Repository: `fyp-xrlids`

```text
PHASE 0 — BASELINE REPOSITORY AUDIT COMPLETE (docs/PROJECT_BASELINE.md)
PHASE 1 — R10-FLOWSEQ SPECIFICATION & MODEL ACCEPTANCE COMPLETE (docs/research/)
PHASE 2 — CORE DATA & FLOW ENGINE (READY TO EXECUTE)
PHASE 3 — RF OPERATIONAL DETECTOR (PLANNED)
PHASE 4 — OPTIONAL TEMPORAL LSTM (PLANNED)
PHASE 5 — DETECTION & RESPONSE ENGINE (PLANNED)
PHASE 6 — BACKEND & FRONTEND INTEGRATION (PLANNED)
PHASE 7 — GENUINE END-TO-END DEMONSTRATION (PLANNED)
PHASE 8 — FINAL EVALUATION & RELEASE READINESS (PLANNED)
PRODUCTION DEPLOYMENT — NOT VALIDATED
```

Phase: **PHASE 0 COMPLETE · PHASE 1 COMPLETE (R10-FlowSeq Approved, Parity Corrected, Multi-Dimensional Acceptance Policy, Fusion Removed) · PHASE 2 READY**
Overall: **Phase 0 Baseline Repository Audit complete (`docs/PROJECT_BASELINE.md`, 602/602 tests passed). Phase 1 Data & Architecture Finalization complete with Option A (R10-FlowSeq) approved, offline/live TCP flag and packet length std parity mathematically resolved and verified via automated tests (`tests/unit/test_r10_flowseq_parity.py`), multi-dimensional LSTM acceptance policy codified, and RF-LSTM fusion formally removed from the approved architecture (`docs/research/MODEL_ACCEPTANCE_CRITERIA.md`). Random Forest certified as the standalone primary operational detector. Ready for Phase 2 Core Data and Flow Engine implementation.**

Legend: ✅ done / verified · 🟡 implemented / empirically observed on partial data · ⛔ blocked on research decision · ⬜ planned / not started

## Phase 1: Data & Architecture Finalization (Completed 2026-10-30)

| Area | Status | Scope / Evidence |
| --- | --- | --- |
| Baseline Audit (Phase 0) | ✅ Complete | Complete repository discovery, artifact checksumming, dependency inventory, and 100% test pass (602 tests in 93.22s) (`docs/PROJECT_BASELINE.md`). |
| Dataset Feasibility Matrix (Phase 1A) | ✅ Verified | Complete schema inspection across 20 CSV files ($7.68\,\text{GB}$). Confirmed CIC-IDS2017 and UNSW-NB15 lack timestamps/IPs. Confirmed CSE-CIC-IDS2018 `Thuesday-20-02-2018` ($7.95\,\text{M}$ rows, $4.05\,\text{GB}$) contains complete 5-tuple, 1-second timestamps, and verified LOIC-HTTP attack labels (`docs/research/TEMPORAL_DATASET_FEASIBILITY.md`). |
| Temporal Data Semantics Audit (Phase 1B) | ✅ Audited & Verified | Complete empirical audit of all 7.95M flows. Discovered 81.9% of benign and 90.9% of attack flows exceed 1.0s duration (mean attack duration 11.89s). Flag counts in CSV are binary 0/1 indicators. Assigned NO-GO on raw packet rates without packet-level data. Proposed authentic `R10-FlowSeq` and `T8-FlowHost` contracts (`docs/research/TEMPORAL_DATA_SEMANTICS_AUDIT.md`). |
| R10-FlowSeq Specification (Phase 1C) | ✅ Approved Specification | Finalized sequence semantics ($K=5$ flows per source host, start-time ordered, 300s session timeout, causal last-flow label). Verified 100% live/offline parity between CSV, R10 contract, and Scapy flow builder. Specified leakage-resistant chronological 70/15/15 splits with 300s purge gaps and 3-host unseen attacker hold-out (`docs/research/R10_FLOWSEQ_FINAL_SPECIFICATION.md`). |
| Scientific Consistency & Parity (Phase 1D) | ✅ Verified & Tested | Verified binary TCP flag indicators ($\min(\text{count}, 1.0)$) preventing $120\sigma$ scaler out-of-distribution distortion; verified population standard deviation ($\text{ddof}=0$) on packet lengths; created automated parity tests (`tests/unit/test_r10_flowseq_parity.py`: 3 passed) (`docs/research/R10_FLOWSEQ_FINAL_SPECIFICATION.md`). |
| Multi-Dimensional Model Acceptance (Phase 1D) | ✅ Formal Policy | Codified multi-dimensional evaluation (Acc, Prec, Rec, F1, PR-AUC, ROC-AUC, FPR $\le 1\%$, unseen-host $F1 \ge 0.85$, latency $< 20\,\text{ms}$, resources) on compatible sequence tasks without forcing single-flow outperformance over RF as sole criterion (`docs/research/MODEL_ACCEPTANCE_CRITERIA.md`). |
| Fusion Removal | ✅ Formal Decision | Score fusion explicitly removed from approved architecture. Zero blended probabilities in operational pipeline. Random Forest functions completely independently (`docs/ARCHITECTURE.md`). |

## Attack-Family Capability & Autonomous Response Integrity (Addendum Verified 2026-10-30)

| Area | Status | Scope / evidence |
| --- | --- | --- |
| Model Prediction Capability Audit | ✅ Verified | All 3 Random Forest artifacts (`CIC-IDS2017`, `CSE-CIC-IDS2018`, `UNSW-NB15`) are strictly binary (`classes_=[0, 1]`) predicting continuous $P(\text{ATTACK})$. No multiclass model exists in repo. |
| Ground-Truth Label Accounting | ✅ Verified | Canonical attack taxonomy defines 17 families across 3 datasets (`configs/labels/label_mapping.yaml`). Evaluated as ground-truth metadata, not model outputs. |
| Per-Family Evaluation Semantics | ✅ Verified | `xrlids.evaluation.error_analysis.compute_per_family_metrics()` computes binary recall/error rate stratified by ground truth family. Never falsely claims to predict family names. |
| DQN Threat-Awareness Scope | ✅ Verified | DQN state vector is strictly 6D causal ($s_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$). Threat-severity aware via continuous score $S_t$; no attack-family label in state. |
| Autonomous Response Safety & Mode | ✅ Verified | Response actions are strictly advisory / dry-run (`response_mode="advisory"`). Deterministic safety gate enforces zero network mutations. Production enforcement remains NO-GO. |
| Flagship Decision Semantics | ✅ Verified | `FlagshipDecision` carries `detection_type="binary"`, `attack_family_prediction=None`, and `response_mode="advisory"`. |
| Dashboard Concept Separation | ✅ Verified | Dedicated semantic contracts in `/api/overview`, `/api/evaluation`, `/api/explainability`, `/api/response-benchmark`, and `/api/live`. Ground-truth families separated from model predictions. |
| Labelled Dataset Replay Lab (10k) | ✅ Implemented & Tested | Interactive replay lab supporting 400, 1,000, 5,000, or 10,000 genuine flow records from CIC-IDS2017, CSE-CIC-IDS2018, or both. Full multi-model routing, 6D causal state updating, Dueling DQN advisory response, on-demand TreeSHAP explanations, and server-side CSV export. |
| Proposed Multiclass Extension | Documented (Future Work) | Feasibility confirmed; frozen artifacts preserved without retraining; formal extension specification recorded in `docs/MODEL_ARTIFACT_AUDIT.md`. |

## Dashboard Flow Evaluation & Exhibition Demo Workflow (Upgraded 2026-10-28)

| Area | Status | Scope / evidence |
| --- | --- | --- |
| Multi-model flow evaluator | Implemented & verified | `src/xrlids/evaluation/csv_evaluator.py`; loads frozen RF (`preprocessor.joblib` + `random_forest.joblib`), Supervised LSTM (`lstm.pt`, $T=5$, causal sequences), and validation-tuned Score Fusion ($\alpha$; blended scores are not calibrated probabilities). |
| Evaluation modes | Implemented | Mode B: 200 Exhibition Demo (`data/demo/cicids2017_exhibition_200.json`, 166 Benign, 34 Attack); Mode A: Full Held-Out Test Evaluation; Mode C: Custom CSV Upload / Paste. |
| Flow network metadata isolation | Implemented & tested | Source/destination endpoints, ports, protocol, and timestamps preserved in metadata sidecar without numeric feature matrix $X$ or label leakage. |
| Explainability & Response Policy | Implemented & tested | On-demand TreeSHAP local feature attribution (`/api/csv/explain`, RF model only); Dueling DQN response recommendations (`models/dqn/dqn_4action_best.pt`, strictly observational `RULE_DRY_RUN`, zero live firewall mutations). |
| Benchmark/feature contract pairing | Implemented & enforced | CIC-IDS2017/R10, CSE-CIC-IDS2018/R10, UNSW-NB15/R4. Mismatches rejected with HTTP 400. |
| Label and feature validation | Implemented with 28 regression tests | Rejects unknown/ambiguous labels; mathematically accounts for invalid/non-finite feature rows; drops NaN/Inf with exact reconciliation. |
| Sequence boundary isolation & segment accounting | Implemented & verified | Detects capture/session boundaries (`source_file`, `session_id`, etc.); strictly isolates sequences per capture; isolates RF tabular evaluation on all rows; documents explicit single-stream fallback when boundary column absent. |
| Dashboard integration | Implemented | `dashboard/server.py`, `dashboard/index.html`, `dashboard/app.js` with mode pills, 3-model metric cards, 3 confusion matrices, flow inspection modal, and server-side CSV export (`/api/csv/export`). |
| Research interpretation | Authoritative evaluation | Preserves historical frozen benchmark artifacts; does not retrain models; distinguishes held-out test splits from demo subsets. |

**Architecture note:** this workflow extends the dashboard's offline evaluation capabilities. It does not replace or fundamentally change the core live pipeline (capture → flow construction → feature extraction → frozen detection model → alert/score presentation). Production deployment remains not validated.

## Implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| Package + pinned environment | ✅ | `pyproject.toml`, `requirements.txt` (Python 3.14.4) |
| Reproducibility utils (seeding, hashing, env fingerprint) | ✅ | `src/xrlids/utils/` |
| Canonical column normalization | ✅ | `src/xrlids/utils/columns.py` (bidirectional mapping, raw provenance preserved) |
| Artifact metadata + sidecars | ✅ | `src/xrlids/artifacts/metadata.py` |
| Centralized metrics (single module) | ✅ | `src/xrlids/evaluation/metrics.py` + tests |
| Label contract + unknown-label rejection | ✅ | `src/xrlids/labels/contract.py` + `configs/labels/label_mapping.yaml` + regression tests |
| Feature definitions + registry + rungs | ✅ | `src/xrlids/features/`; candidate rungs R10/R15/R20 + 4-feature transfer contract |
| Feature computation + canonical column maps | ✅ | `src/xrlids/features/compute.py` + tests (CIC-IDS2017 R10 verified) |
| Feature compatibility matrix | ✅ | `reports/generated/feature_compatibility.md` |
| Cleaning + row accounting | ✅ | `src/xrlids/preprocessing/cleaning.py` + tests |
| Multi-file dataset population loader | ✅ | `src/xrlids/datasets/population.py` (reconciled accounting, conflict resolution) |
| Chunked streaming data pipeline | ✅ | `src/xrlids/preprocessing/streaming.py` + equivalence tests |
| Leakage-safe splits + leakage audit | ✅ | `src/xrlids/splitting/` + tests |
| Preprocessing (train-only fit) | ✅ | `src/xrlids/preprocessing/pipeline.py` + tests |
| Baseline ladder detectors (Majority, LR, DT) | ✅ | `src/xrlids/models/baselines.py` + tests |
| Memory-bounded Random Forest (capped parallelism) | ✅ | `src/xrlids/models/random_forest.py` (`n_jobs=min(4, os.cpu_count())`) |
| Memory-bounded Supervised LSTM (lazy sequence batching) | ✅ | `src/xrlids/models/lstm.py` (`SequenceArray` on-the-fly mini-batching) |
| Fusion (aligned populations) | ✅ | `src/xrlids/models/fusion.py` + tests |
| Calibration (Brier/ECE/reliability/Platt) | ✅ | `src/xrlids/evaluation/calibration.py` + tests |
| Threshold sweep + candidate operating points | ✅ | `src/xrlids/evaluation/thresholding.py` + tests |
| Statistical hypothesis testing & paired bootstrap | ✅ | `src/xrlids/evaluation/statistics.py` (empirical 95% CIs, p-values) |
| Per-attack-family evaluation | ✅ | `src/xrlids/evaluation/error_analysis.py` + tests |
| Experiment registry + result metadata | ✅ | `src/xrlids/experiments/registry.py` |
| Dataset manifest + checksum enforcement | ✅ | `src/xrlids/datasets/loading.py` (`verify_dataset_file`) + tests |
| Dataset acquisition workflow (register/verify) | ✅ | `src/xrlids/datasets/prepare.py` + `scripts/phase1/prepare_dataset.py` + tests |
| Real-file schema validation (canonical headers) | ✅ | `src/xrlids/datasets/schema.py` + tests |
| Real-data per-file streaming audit runner | ✅ | `scripts/phase1/03_run_audit.py` (25 structured audit fields per file) |
| Unified experiment runner + pre-flight gate | ✅ | `scripts/phase1/run_experiment.py` + `src/xrlids/experiments/preflight.py` (10-point check) |
| Resource profiler (instantaneous RSS, peak ru_maxrss) | ✅ | `src/xrlids/utils/profiler.py` + tests |
| Baseline experiment configs | ✅ | `configs/experiments/` |
| Dataset audit module | ✅ | `src/xrlids/datasets/audit.py` + tests |
| CLI | ✅ | `src/xrlids/cli.py` |
| Report generation from artifacts | ✅ | `scripts/phase1/generate_reports.py` (dynamic git hashes, live manifests) |
| Test suite | ✅ | 584 unit, data, integration, model, capture, and pipeline tests passing (0 failures); complete Phase 1, Phase 2, Phase 3, Replay Lab, and Scapy capture & unified inference verification suite |
| Scapy Capture & PCAP Ingestion Service | ✅ Implemented & Tested | `src/xrlids/capture/scapy_service.py` (thread-safe, non-blocking queue, BPF filtering, error accounting, throughput counters) + `tests/unit/test_scapy_capture.py` (5 tests passing) |
| Unified Inference & Sequence Buffer Service | ✅ Implemented & Tested | `src/xrlids/models/inference_service.py` (thread-safe session sliding-window $T=5$ buffer, dynamic model loading, RF/LSTM/Fusion dispatch, latency instrumentation) + `tests/unit/test_unified_inference_service.py` (4 tests passing) |
| End-to-End Pipeline Integration Test | ✅ Implemented & Tested | `tests/integration/test_end_to_end_scapy_pipeline.py` (2 tests passing: full Scapy PCAP → LiveFlowBuilder → UnifiedInference → TreeSHAP → StateBuilder → DuelingQNetwork → DeterministicSafetyGate causal loop, plus 5-flow LSTM sequence fusion activation) |
| SHAP explainability module | ✅ | `src/xrlids/explainability/shap_analysis.py` + tests |
| Cross-dataset transfer module | ✅ | `src/xrlids/experiments/transfer.py` + `scripts/phase1/run_transfer.py` + configs (6 directions executed) |
| Pure-Python PCAP reader / writer | ✅ | `src/xrlids/demo/pcap.py` (zero external C-dependencies) + tests |
| Streaming Bidirectional Flow Builder | ✅ | `src/xrlids/demo/flow.py` (D-006 hybrid policy: FIN/RST + 120s timeout) + tests |
| Live Feature Parity Verifier | ✅ | `src/xrlids/demo/extractor.py` + `tests/integration/test_feature_parity.py` ($\text{atol} \le 10^{-4}$) |
| PCAP Replay Demonstration Engine | ✅ | `src/xrlids/demo/replay.py` + `scripts/demo/run_replay_demo.py` + `results/demo/` |
| Safe Observational Live Lab Monitor | ✅ | `src/xrlids/demo/live_lab.py` (alert-only, zero network mutation) + tests |
| Autonomous Response Simulation & Safety Gate | ✅ | `src/xrlids/response/` (causal 6D state, deterministic safety gate, consequence engine, research cost matrix) + tests |
| Autonomous Response Baseline Ladder (Phase 2A) | ✅ | `src/xrlids/response/baselines.py`, `runner.py`, `scripts/phase2/run_phase2a_baselines.py` + tests |
| Deep Q-Network Autonomous Response Policy (Phase 2B) | ✅ | `src/xrlids/response/dqn/`, `results/phase2/EXP-P2B-DQN-001` (Dueling DQN + PER) |
| State Feature Ablation & Sensitivity Matrix (Phase 2C) | ✅ | `results/phase2/EXP-P2C-SENSITIVITY-001` (6 single-dim + joint ablations) |
| Cross-Dataset Robustness & Score Jitter Stress (Phase 2D) | ✅ | `results/phase2/EXP-P2D-ROBUSTNESS-001` (transfer safety & noise sweep) |
| Dual-Layer Explainability Engine & Audit Cards (Phase 2E) | ✅ | `src/xrlids/response/explainability/`, `results/phase2/EXP-P2E-EXPLAINABILITY-001` (28,167 cards) |
| Held-Out Final Test Evaluation (EXP-P2-FINAL-TEST-001) | ✅ | Single authoritative evaluation on 355,865 $D_{\text{pol\_test}}$ flows |
| PacketCaptureService (Phase 3A) | ✅ | `src/xrlids/live/capture.py` (AF_PACKET raw socket / PCAP / synthetic streams) + tests |
| Passive WiFi Device Discovery | ✅ implemented (live-only) | `src/xrlids/live/devices.py` (ARP/DHCP/mDNS/SSDP + neighbour cache; no probes/scans) + `/api/live/devices` and UI panel |
| Live Flow Construction under D-006 (Phase 3B) | ✅ | `src/xrlids/live/flow_builder.py` (5-tuple, FIN/RST teardown, 120s idle timeout) + tests |
| Live Feature Parity Verification Harness (Phase 3C) | ✅ | `src/xrlids/live/parity.py`, `docs/phase3/LIVE_FEATURE_PARITY.md` ($\text{atol} \le 10^{-4}$) + tests |
| Dry-Run Autonomous Pipeline Runner (Phase 3B/3C) | ✅ | `src/xrlids/live/runner.py` (strict zero network mutation, fail-safe invariants) + tests |
| Controlled Response Safety & Rollback Architecture | ✅ | `docs/phase3/CONTROLLED_RESPONSE_SAFETY.md` (atomic rollback specification) |
| Controlled Traffic Taxonomy Specification | ✅ | `docs/phase3/CONTROLLED_UNSEEN_TRAFFIC.md` (8 distinct traffic tiers) |
| Controlled 1000-Packet Burst Experiment (Phase 3E) | ✅ | `src/xrlids/live/burst.py`, `scripts/phase3/run_burst_experiment.py`, `results/phase3/EXP-P3-BURST-1000-001/` |
| Enforcement Readiness & Activation Gate (Phase 3H) | ✅ | `src/xrlids/enforcement/gate.py` (PreconditionGate, LabActivationAuthorization, EnforcementEligibility) + tests |
| Isolated Lab Network Namespace Topology & Response Loop (Phase 3I) | ✅ | `src/xrlids/enforcement/lab.py` (HostNetworkBaseline, IsolatedLabEnvironment, NetnsActuatorBackend) + tests |
| Multi-Flow Soak & Shared-State Concurrency (Phase 3J) | ✅ | `src/xrlids/enforcement/concurrency.py`, `src/xrlids/response/transaction.py` (TargetLockManager, ConcurrencyHarness, MultiFlowTrafficGenerator) + tests |
| Pre-Production Security & Stress Audit (Phase 3K) | ✅ | `src/xrlids/enforcement/stress.py`, `scripts/phase3/run_security_stress_experiment.py`, `results/phase3/EXP-P3K-STRESS-SECURITY-001/` (10k flows, 29 attacks, 8 tamper, 12 failure injections, 100 rollbacks) + tests |

## Empirical status

| Experiment | Status | Reason / Evidence |
| --- | --- | --- |
| Dataset acquisition | ✅ VERIFIED | All 20 physical CSV files acquired and verified against canonical manifest (8 CIC-IDS2017, 10 CSE-CIC-IDS2018, 2 UNSW-NB15) |
| Dataset audit (real files) | ✅ COMPLETED | All 20 files audited via chunked streaming with per-file JSON artifacts in `results/audits/` |
| Splits / leakage (real data) | ✅ VALIDATED | Policy A feature-dedup random split passes L-01/L-02 cleanly (0 cross-split duplicate vectors); strict temporal holdout passes L-01/L-02/L-05 (`EXP-P1-CSE2018-TEMPORAL-R10-001`, `leakage_report.json`) |
| CIC-IDS2017 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across all 8 files (2,830,743 raw rows -> 1,779,322 modeling rows); baseline ladder evaluated (`EXP-P1-CIC2017-R10-001`, RF test acc=0.9815, F1=0.9512) |
| CSE-CIC-IDS2018 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across all 10 files (16,233,002 raw rows -> 8,312,295 modeling rows); baseline ladder evaluated (`EXP-P1-CSE2018-R10-MULTI-001`, RF test acc=0.9723, F1=0.8861, ROC-AUC=0.9902) |
| UNSW-NB15 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across both files (257,673 raw rows -> 122,520 modeling rows); full baseline ladder, Supervised LSTM, and RF+LSTM Fusion evaluated under native 4-feature contract (`EXP-P1-UNSWNB15-R10-MULTI-001`, Fusion test acc=0.8996, F1=0.8970, ROC-AUC=0.9674) |
| Supervised LSTM (Multi-file) | ✅ EMPIRICALLY OBSERVED (ALL 3 DOMAINS) | Full multi-file training executed on CIC-IDS2017 (F1=0.9633), CSE-CIC-IDS2018 (F1=0.9603), and UNSW-NB15 (F1=0.8637, outperforming RF with $\text{LSTM} - \text{RF} = +0.0089$, $p=0.0000$) |
| Score Fusion (Multi-file) | ✅ EMPIRICALLY OBSERVED (ALL 3 DOMAINS) | Tuned fusion evaluated on CIC-IDS2017 ($\alpha=0.50$, F1=0.9745), CSE-CIC-IDS2018 ($\alpha=0.00$, F1=0.9603), and UNSW-NB15 ($\alpha=0.60$, F1=0.8970; $\Delta \text{F1}=+0.0421$ over RF, $\Delta \text{F1}=+0.0332$ over LSTM, $p=0.0000$) |
| Multi-seed evaluation | ✅ COMPLETED | 3-seed sweep (42/123/456) executed across all three benchmarks (2026-10-17); seed 42 reproduces frozen artifacts exactly; mean ± std in `reports/generated/multi_seed_report.md` |
| Temporal / grouped split validation | ✅ COMPLETED (TEMPORAL) | Strict future-day holdout executed (`EXP-P1-CSE2018-TEMPORAL-R10-001`): 5,053,051 train / 1,627,614 validation / 1,631,630 test, train 14–20 Feb and test 22 Feb–2 Mar 2018. RF F1 0.0113 (recall 0.0068, ROC-AUC 0.3905) vs random-split F1 0.8861; bot recall 99.17% → 0.09%, infiltration 10.70% → 0.94%. Temporal test is 3.08% attacks after Policy A dedup (50,306 unique future attacks). L-01/L-02/L-05 pass; `reports/generated/temporal_split_report.md`. Grouped-by-host split not executed (no stable host key) |
| Bootstrap confidence intervals | ✅ COMPLETED | Per-seed 95% bootstrap CIs computed from the saved held-out test predictions for CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, and the CSE temporal holdout (B=1000; `reports/generated/bootstrap_ci_report.md`; per-experiment `bootstrap_cis.json`). CIs quantify test-set sampling uncertainty; training-seed variance remains in `reports/generated/multi_seed_report.md` |
| Cross-dataset transfer | ✅ EMPIRICALLY OBSERVED | Executed across all 6 directions: Primary R10 (CIC ↔ CSE) and Auxiliary R4 (UNSW ↔ CIC, UNSW ↔ CSE); severe domain degradation demonstrated (ΔF1 -0.52 to -0.95), answering RQ5 |
| SHAP (real data) | ✅ EMPIRICALLY OBSERVED | TreeSHAP evaluated on CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 Random Forest models |
| Calibration (real data) | ✅ EMPIRICALLY OBSERVED | Platt scaling evaluated on CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 models |
| Threshold objective | ✅ FRAMEWORK RESOLVED | D-003 governance framework resolved; operational threshold selection remains open. Research reporting baseline frozen at $\tau = 0.50$; $\tau_{\text{ops}} = 0.40$ designated strictly as proposed Phase 2 operational candidate pending deployment loss evidence |
| Live Replay & Demonstration Foundation | ✅ EMPIRICALLY OBSERVED & VERIFIED | End-to-end packet replay, flow accumulation, R10 feature parity ($\text{atol} \le 10^{-4}$), RF model inference, and demonstration artifacts verified in `results/demo/` |
| Autonomous Response Baseline Ladder (Phase 2A) | ✅ EMPIRICALLY OBSERVED & VERIFIED | Evaluated across 24 configurations (4 baselines x 3 cost regimes x 2 action modes) on 142,346 $D_{\text{pol\_val}}$ flows (`EXP-P2A-BASELINES-001`, B=1000 bootstrap tests); D-003 preserved, D_pol_test strictly untouched |
| Controlled 1000-Packet Traffic Burst (Phase 3E) | ✅ EMPIRICALLY OBSERVED & VERIFIED | Executed across 1000 packets (800 benign + 200 attack) in `LiveMode.DRY_RUN` (`EXP-P3-BURST-1000-001`, `REPORT-P3E-BURST-1000-001`); 100% consumed, 0 synthetic drops, 0 mutations, 270/270 audit cards, component latencies P50/P95/P99 profiled |
| Cost-Optimal Benchmark (Phase 2A) | ✅ EMPIRICALLY OBSERVED & VERIFIED | Evaluated zero-parameter analytic Cost-Optimal policy vs trained DQN on 355,865 test flows (`EXP-P2A-COST-OPTIMAL-001`); Cost-Optimal beats DQN in 4/6 settings (e.g. 20.12% lower cost in 4-action HA); DQN reduces cost by only 8.8% in remaining 2 settings (failing 15% target) |
| Forensic Readiness Audit (Phase 2B) | ✅ EMPIRICALLY AUDITED & VERIFIED | Full repository forensic readiness audit (`EXP-P2B-READINESS-AUDIT-001`); all 9 canonical models hash-verified; population discrepancy reconciled (355,865 tabular vs 355,833 sequence-aligned flows); 6/6 safety gate invariant tests passed; Go for academic/lab/monitoring, No-Go for production autonomous response |
| Live Observability & Fault Injection (Phase 3F) | ✅ EMPIRICALLY OBSERVED & AUDITED | Multi-condition execution on 1000 packets (nominal, queue backpressure, and 6 failure injection scenarios) in `LiveMode.DRY_RUN` (`EXP-P3F-OBSERVABILITY-001`, `REPORT-P3F-OBSERVABILITY-001`); 6/6 failure scenarios verified, fail-safe invariant proven, zero network mutations |
| Atomic Rollback & Response Transaction Harness (Phase 3G) | ✅ EMPIRICALLY OBSERVED & AUDITED | Evaluated across 12 deterministic scenarios (`EXP-P3G-ROLLBACK-001`, `REPORT-P3G-ROLLBACK-001`); atomic lifecycle, SHA-256 snapshots, auto-compensation rollback, watchdog TTL monitoring, idempotency, and permanent `SAFETY_LOCKED` latch verified under zero network mutation |
| Enforcement Readiness & Activation Gating (Phase 3H) | ✅ EMPIRICALLY OBSERVED & AUDITED | Evaluated across 18 deterministic scenarios (`EXP-P3H-ENFORCEMENT-GATE-001`, `REPORT-P3H-ENFORCEMENT-GATE-001`); fail-closed PreconditionGate, SHA-256 evidence validation, exact commit binding, signed LabActivationAuthorization, and non-bypassability verified; READY != ENFORCEMENT enforced with 0 host network mutations |
| Isolated Lab Namespace & Response Loop (Phase 3I) | ✅ EMPIRICALLY OBSERVED & AUDITED | Evaluated across 16 sequential stages and 16 failure injection scenarios (`EXP-P3I-ISOLATED-LAB-001`, `REPORT-P3I-ISOLATED-LAB-001`); dual-mode topology, host cryptographic baseline comparison (0 host mutations guaranteed), verified rollback, and deterministic cleanup verified |
| Multi-Flow Soak & Concurrency Stress (Phase 3J) | ✅ EMPIRICALLY OBSERVED & AUDITED | Evaluated across 192 total transactions (185 committed, 3 rolled back, 4 aborted, 0 safety locked), 120 flows, 2,863 packets, 12 concurrent failure injection scenarios (`EXP-P3J-CONCURRENCY-001`, `REPORT-P3J-CONCURRENCY-001`); striped per-target locking, target-scoped state rollback, and zero host network mutations verified |
| Pre-Production Security & Stress Audit (Phase 3K) | ✅ EMPIRICALLY OBSERVED & AUDITED | Evaluated across 10,000 flows (222,838 packets), 4 socket stress tiers, 29 adversarial attack surface vectors (29/29 pass), 8 cryptographic provenance tamper tests (8/8 pass), 100 mixed rollback stress transactions (100% success), 12 active soak failure scenarios (12/12 pass), zero host mutations verified (`EXP-P3K-STRESS-SECURITY-001`, `PHASE3K_SECURITY_STRESS_REPORT.md`) |



## Research decisions status

| ID | Decision | Status |
| --- | --- | --- |
| D-001 | Normalization & Cleaning contract | RESOLVED: Canonical column contract established with preserved raw provenance |
| D-002 | Feature contract R10/R15/R20 | RESOLVED: R10 frozen as Main Cross-Dataset 10-Feature Contract for CIC-IDS2017/CSE-CIC-IDS2018; UNSW-NB15 blocked on 6 missing features (auxiliary fallback) |
| D-003 | Threshold objective | FRAMEWORK RESOLVED (Research reporting baseline $\tau = 0.50$ frozen; Operational threshold selection remains open pending Phase 2 deployment loss evidence; $\tau_{\text{ops}} = 0.40$ is a proposed candidate only) |
| D-004 | Dataset acquisition | RESOLVED: All 20 modeling files acquired, verified, and audited |
| D-005 | Cross-dataset normalisation | RESOLVED: Strict source-only preprocessing fit (zero target data leakage) under frozen semantic contracts (R10 for CIC ↔ CSE, R4 for UNSW) |
| D-006 | Flow timeout / completion policy | RESOLVED: Option D (Hybrid flow completion policy: TCP FIN/RST completion, 120.0s idle timeout fallback) |

## Explicitly not claimed

- No claims of universal performance or production readiness across arbitrary networks.
- No claims that intrusion detectors generalize out-of-domain without target adaptation; empirical evaluation across all 6 cross-dataset pairs demonstrates 52% to 95% F1 degradation under unadapted transfer (answering RQ5).
- In auxiliary transfers involving UNSW-NB15, source models were trained under the common 4-feature (R4) contract; original 10-feature models were not directly evaluated on UNSW due to missing features.
- No claims that sequence models capture true physical packet arrival timelines; sequence ordering represents capture flow arrival order within sample partitions.
- No claims that the frozen headline artifacts are three-seed averages; headline figures reflect single-seed (seed=42) execution. The separate 3-seed robustness sweep (seeds 42/123/456, `reports/generated/multi_seed_report.md`) is reported as stability evidence only.
- Live lab monitor and Phase 3 dry-run pipelines are strictly observational / non-disruptive; ZERO system firewall, socket, routing, or interface mutations are performed.
- Auxiliary event list `UNSW-NB15_LIST_EVENTS.csv` is absent (`DATA_NOT_AVAILABLE`); modeling relies solely on the two verified train/test partitions.
- Phase 2 offline response research and held-out evaluation is scientifically frozen (`11f32f658cde525300f8bc46088a0143e8329c21`); all cost models and state transitions were evaluated offline under pre-registered audit criteria.
- Controlled response enforcement has been validated strictly within an isolated laboratory Linux network namespace environment (10.200.1.0/24); production deployment is not validated and remains strictly out of scope.
- No claims that the trained DQN achieves general cost superiority over zero-parameter analytic cost-optimal baselines; `EXP-P2A-COST-OPTIMAL-001` empirically demonstrated that `CostOptimalThresholdPolicy` achieves lower cost in 4 of 6 benchmark settings (by up to 20.12% lower cost in 4-action HA).
- No claims that the response simulator is a sequential closed-loop Markov Decision Process; traffic arrivals are strictly exogenous replay, and the environment is formally an Asymmetric-Loss Contextual Bandit with Hysteresis Constraints.
- No claims that CSE-CIC-IDS2018 fusion represents multi-model synergy; the optimal fusion weight is $\alpha = 0.00$, making the result an LSTM-only detector output.
- No claims that raw Random Forest voting probabilities represent calibrated Bayesian attack probabilities; severe probability distortion (~10× overconfidence) is present in intermediate score bins.
- No claims of operational detection accuracy are made on unmanaged live network traffic in the absence of independent ground-truth labeling (§64).
- `CLAIMS_REGISTRY.md` records only scoped, traceable empirical claims directly supported by committed `results/` artifacts.
