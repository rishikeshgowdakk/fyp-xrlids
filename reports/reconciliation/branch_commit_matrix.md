# XRL-IDARS — Branch Commit Matrix & Ancestry Forensic Audit

**Audit Date:** October 30, 2026  
**Auditor:** Senior Git Release Engineer and Technical Lead  
**Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Reconciliation Target:** `integration/preserve-main-and-final`  

---

## 1. Branch Topology and Merge Base

```
                    o---o---o---o---o [18 commits: XGBoost, Multiclass, Feature Sweep, Pairings]
                   /                                                                             \
---o [6408f5e] ---                                                                                o [7c2bacd]
   (Merge Base)    \                                                                             /  (Reconciliation Commit)
                    o---o---o---o---o---o---o [9 commits: Theme-UI, Scapy Live, DQN Audit, R10] /
```

- **Common Ancestor (Merge Base):** `6408f5e82c5dcd81bd356973a74eb109f233be9e`
  - *Commit Message:* `feat(demo): add dedicated Scapy attack simulator and Viva frontend (#13)`
  - *Timestamp:* 2026-10-30T09:37:04+01:00
- **Parent 1 (`main`):** `934cf62eb5503b260067688fa64e8ef6f5a49a94`
  - *Commit Message:* `docs(report): formalise champion model selection and master update`
- **Parent 2 (`feature/final-acceptance-integration`):** `2ea850e3a9757980f458bf7284e865d59697a913`
  - *Commit Message:* `docs(audit): establish final acceptance audit and formal compliance card`
- **Reconciliation Merge Commit:** `7c2bacd4676d50ade1960a78e692d0d0ee8ae564` on branch `integration/preserve-main-and-final`

---

## 2. Ancestry Lineage of Related Branches

| Branch Name | Head SHA | Ancestry & Relationship to Merge Base |
|:---|:---|:---|
| `main` | `934cf62eb5503b260067688fa64e8ef6f5a49a94` | Direct descendant of merge base `6408f5e` (+18 commits). Contains XGBoost candidates, 8D research DQN, feature rung sweep, and detector-to-DQN pairings. |
| `engineering/theme-ui` | `c2b2b29b213a1fa3c6748f4e7c63b0172ec73b39` | Direct descendant of merge base `6408f5e` (+6 commits). Established streamlined dashboard theme, component layout, and frontend styling. |
| `feature/scapy-live-demo` | `3543369d4bd9834b79d8065302455ac8a07838a3` | Direct descendant of `engineering/theme-ui` (+1 commit). Added live Scapy demonstration scripts and lab harness. |
| `feature/final-acceptance-integration` | `2ea850e3a9757980f458bf7284e865d59697a913` | Direct descendant of `feature/scapy-live-demo` (+2 commits: `48b8f7c` and `2ea850e`). Added R10 flowseq parity tests, DQN audit, and autonomous response validation. |
| `integration/preserve-main-and-final` | `7c2bacd4676d50ade1960a78e692d0d0ee8ae564` | **Reconciled two-parent merge** uniting `main` and `feature/final-acceptance-integration` without rewriting history. |

---

## 3. Commits Unique to `main` (18 Commits)

These commits represent empirical research, candidate detector evaluations, and feature sweeps developed on `main`:

| Index | Commit SHA | Author | Commit Message Summary |
|:---:|:---:|:---:|:---|
| 1 | `327a31e` | Rishikesh Gowda | `feat(ml): implement native XGBoost detector wrapper and test suite` |
| 2 | `295a755` | Rishikesh Gowda | `docs(audit): complete comprehensive repository and model artifact audit` |
| 3 | `b1e06fa` | Rishikesh Gowda | `feat(ingestion): implement canonical 5-tuple flow builder and live capture service` |
| 4 | `1bc4b5f` | Rishikesh Gowda | `feat(ml): implement genuine TreeSHAP explainer for RF and XGBoost` |
| 5 | `10bc938` | Rishikesh Gowda | `feat(rules): implement protocol rule engine and hybrid arbitration matrix` |
| 6 | `6c1e550` | Rishikesh Gowda | `feat(tracking): implement multi-flow source activity tracker` |
| 7 | `8ca75ec` | Rishikesh Gowda | `feat(response): implement trained dueling DQN response policy and safety gate` |
| 8 | `1c890ce` | Rishikesh Gowda | `feat(pipeline): implement active inference pipeline orchestrator` |
| 9 | `c0d7f97` | Rishikesh Gowda | `feat(dashboard): build operational Streamlit command center` |
| 10 | `a49dcff` | Rishikesh Gowda | `docs(arch): deliver complete master architectural documentation` |
| 11 | `15e98c7` | Rishikesh Gowda | `test(suite): achieve 100% test pass rate across 616 tests` |
| 12 | `36c4b28` | Rishikesh Gowda | `feat(multiclass): train and evaluate 6-class RF attack attribution classifier` |
| 13 | `2ef496b` | Rishikesh Gowda | `feat(response): implement autonomous response execution engine with rollback` |
| 14 | `a3e3518` | Rishikesh Gowda | `feat(experiments): complete empirical feature rung sweep (R4, R10, R15, R20, R30)` |
| 15 | `86cae74` | Rishikesh Gowda | `feat(dqn): train dual-track DQN policies (Track B1 Binary & Track B2 Attack-Aware)` |
| 16 | `1f3c30d` | Rishikesh Gowda | `feat(benchmarks): execute comparative policy benchmark (B=1,000 paired bootstraps)` |
| 17 | `9e54a93` | Rishikesh Gowda | `feat(integration): benchmark 4 detector-to-DQN pairings across 3 datasets` |
| 18 | `934cf62` | Rishikesh Gowda | `docs(report): formalise champion model selection and master update` |

---

## 4. Commits Unique to `feature/final-acceptance-integration` (9 Commits)

These commits represent the operational acceptance platform, Scapy wire simulation, DQN audit, and R10 flowseq parity:

| Index | Commit SHA | Author | Commit Message Summary |
|:---:|:---:|:---:|:---|
| 1 | `5250629` | Rishikesh Gowda | `feat(capture): implement scapy packet capture and live inference wiring` |
| 2 | `a9634e9` | Rishikesh Gowda | `docs(testing): document scapy capture and unified inference test coverage` |
| 3 | `ebe9c5e` | Rishikesh Gowda | `docs(architecture): update system architecture and data flow documentation` |
| 4 | `11d735d` | Rishikesh Gowda | `docs(exhibition): add live capture and replay demonstration runbooks` |
| 5 | `94bc3c2` | Rishikesh Gowda | `test(runner): wire live pipeline runner to inference service with unit test` |
| 6 | `c2b2b29` | Rishikesh Gowda | `docs(theme): record theme-ui branch baseline and clean working tree status` |
| 7 | `3543369` | Rishikesh Gowda | `feat(acceptance): implement live scapy attack simulation and viva demo interface` |
| 8 | `48b8f7c` | Rishikesh Gowda | `fix(acceptance): correct audit findings, flowseq consistency, and research baseline` |
| 9 | `2ea850e` | Rishikesh Gowda | `docs(audit): establish final acceptance audit and formal compliance card` |

---

## 5. File Inventory Reconciled

Across the 1,310 target files audited in Phase 1:
- **1,073 files** were bit-for-bit identical across both branches.
- **123 files** were unique to `main` (all preserved on `integration/preserve-main-and-final`).
- **80 files** were unique to `feature/final-acceptance-integration` (all preserved on `integration/preserve-main-and-final`).
- **34 files** were modified on both sides:
  - 20 files merged automatically by Git without conflict.
  - 14 files required surgical conflict resolution (fully documented in `reports/reconciliation/conflict_resolution_log.md`).

**Conclusion:** 100% of historical commits, files, and research artifacts from both development lines are preserved.
