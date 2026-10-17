# XRL-IDARS v1 — EXPERIMENT INDEX

> **Scope:** Authoritative index of all empirical experiments across Phase 1, Phase 2, and Phase 3.  
> **Status:** AUDITED & FROZEN  
> **Baseline Commit:** `31c47308703ec22727078e3a62f518ab33b3173d` (`v1.0.0`)

---

## Master Experiment Registry

| Experiment ID | Phase | Purpose | Dataset / Traffic Source | Main Artifact Location | Summary Result | Baseline Commit |
|:---|:---:|:---|:---|:---|:---|:---:|
| `AUDIT-001` | Phase 1 | Chunked streaming audit of raw CSVs | 20 CSV files (CIC, CSE, UNSW) | `results/audits/` | 100% schema integrity; identified duplication | `11f32f6` |
| `EXP-P1-CIC2017-R10-001` | Phase 1 | Evaluate RF, LSTM, and Fusion under R10 | CIC-IDS2017 (8 files, 1.78M modeling rows) | `results/experiments/EXP-P1-CIC2017-R10-001/` | RF F1=0.9512, LSTM F1=0.9633, Fusion F1=**0.9745** | `11f32f6` |
| `EXP-P1-CSE2018-R10-MULTI-001` | Phase 1 | Evaluate RF, LSTM, and Fusion under R10 | CSE-CIC-IDS2018 (10 files, 8.31M modeling rows) | `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/` | RF F1=0.8861, LSTM F1=**0.9603**, Fusion F1=**0.9603** | `11f32f6` |
| `EXP-P1-UNSWNB15-R10-MULTI-001` | Phase 1 | Evaluate auxiliary R4 contract baselines | UNSW-NB15 (2 files, 122.5k modeling rows) | `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/` | RF F1=0.8548, LSTM F1=0.8637, Fusion F1=**0.8970** | `11f32f6` |
| `EXP-P1-MULTISEED-001` | Phase 1 | 3-seed robustness sweep (42/123/456) across headline benchmarks | CIC-IDS2017 · CSE-CIC-IDS2018 · UNSW-NB15 | `results/experiments/EXP-P1-*/seed_*/` | Seed 42 reproduces frozen artifacts exactly; Fusion acc 0.9903±0.0005 / 0.9912±0.0001 / 0.8988±0.0008 | `4798758` |
| `EXP-P1-TRANSFER-CIC-CSE` | Phase 1 | Unadapted domain shift evaluation | CIC-IDS2017 $\to$ CSE-CIC-IDS2018 | `results/cross_dataset/` | F1 collapsed from 0.9512 to 0.4312 (-54.6%) | `11f32f6` |
| `EXP-P1-TRANSFER-CSE-CIC` | Phase 1 | Unadapted domain shift evaluation | CSE-CIC-IDS2018 $\to$ CIC-IDS2017 | `results/cross_dataset/` | F1 collapsed from 0.8861 to 0.3120 (-64.8%) | `11f32f6` |
| `EXP-P1-TRANSFER-UNSW-CIC`| Phase 1 | Cross-domain evaluation under R4 | UNSW-NB15 $\to$ CIC-IDS2017 | `results/cross_dataset/` | Severe degradation (F1 collapse > 70%) | `11f32f6` |
| `EXP-P1-TRANSFER-UNSW-CSE`| Phase 1 | Cross-domain evaluation under R4 | UNSW-NB15 $\to$ CSE-CIC-IDS2018 | `results/cross_dataset/` | Severe degradation (F1 collapse > 70%) | `11f32f6` |
| `EXP-P2A-BASELINES-001` | Phase 2 | Benchmark 4 deterministic heuristics | 142,346 $D_{\text{pol\_val}}$ flows | `results/phase2/EXP-P2A-BASELINES-001/` | Established operational cost bounds | `11f32f6` |
| `EXP-P2B-DQN-001` | Phase 2 | Dueling DQN training with PER | $D_{\text{pol\_train}}$ flows | `results/phase2/EXP-P2B-DQN-001/` | Policy converged; stable Q-values | `11f32f6` |
| `EXP-P2C-SENSITIVITY-001` | Phase 2 | 6D State feature ablation | $D_{\text{pol\_val}}$ flows | `results/phase2/EXP-P2C-SENSITIVITY-001/` | Detector score & family carry >80% policy value | `11f32f6` |
| `EXP-P2D-ROBUSTNESS-001` | Phase 2 | Score jitter & OOD stress testing | $D_{\text{pol\_val}}$ flows + Gaussian noise | `results/phase2/EXP-P2D-ROBUSTNESS-001/` | Policy sensitive to uncalibrated detector noise | `11f32f6` |
| `EXP-P2E-EXPLAINABILITY-001` | Phase 2 | Generate dual-layer audit cards | 28,167 sampled decision flows | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` | 28,167 audit cards generated with SHAP attributions | `11f32f6` |
| `EXP-P2-FINAL-TEST-001` | Phase 2 | Authoritative held-out test evaluation | 355,865 $D_{\text{pol\_test}}$ flows | `results/phase2/EXP-P2-FINAL-TEST-001/` | Cost reduction: +11.29% (Bal), +14.10% (Agg); $\ge 15\%$ NOT MET | `11f32f6` |
| `DEMO-REPLAY-001` | Phase 3 | PCAP replay & streaming demonstration | Synthetic / recorded PCAP traces | `results/demo/` | Feature parity verified ($\text{atol} \le 10^{-4}$) | `724969a` |
| `EXP-P3-BURST-1000-001` | Phase 3 | Controlled 1,000-packet traffic burst | 1,000 packets (800 benign, 200 attack) | `results/phase3/EXP-P3-BURST-1000-001/` | DRY_RUN only; median inference 47.6 ms/flow | `09fc828` |
| `EXP-P3F-OBSERVABILITY-001` | Phase 3 | Observability & backpressure handling | 1,000 packets + queue stress | `results/phase3/EXP-P3F-OBSERVABILITY-001/` | 6/6 failure scenarios verified; fail-safe engaged | `8db5682` |
| `EXP-P3G-ROLLBACK-001` | Phase 3 | Atomic transaction rollback harness | Simulated actuator backend | `results/phase3/EXP-P3G-ROLLBACK-001/` | 12/12 scenarios passed; SAFETY_LOCKED verified | `05587f7` |
| `EXP-P3H-ENFORCEMENT-GATE-001`| Phase 3 | Provenance gate & token authorization | Multi-precondition verification bundle | `results/phase3/EXP-P3H-ENFORCEMENT-GATE-001/` | 18/18 scenarios passed; fail-closed gate proven | `3e62fba` |
| `EXP-P3I-ISOLATED-LAB-001` | Phase 3 | Isolated lab network namespace loop | Lab netns (`10.200.1.0/24`) | `results/phase3/EXP-P3I-ISOLATED-LAB-001/` | 16/16 stages passed; 0 host network mutations | `ed9bd59` |
| `EXP-P3J-CONCURRENCY-001` | Phase 3 | Multi-target concurrency stress | 120 flows, 2,863 packets, 8 workers | `results/phase3/EXP-P3J-CONCURRENCY-001/` | 192 txs (185 commit, 3 rb, 4 abort); 0 host mutations | `4e06e71` |
| `EXP-P3K-STRESS-SECURITY-001` | Phase 3 | Formal security & high-volume stress | 10,000 flows (222,838 packets) | `results/phase3/EXP-P3K-STRESS-SECURITY-001/` | 29/29 attacks pass; 8/8 tamper pass; 100 rb pass; 0 host mut | `f600bfb` |
