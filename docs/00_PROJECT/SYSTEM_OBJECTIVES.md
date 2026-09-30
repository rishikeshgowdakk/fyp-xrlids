# SYSTEM OBJECTIVES

Status: **frozen**

Objectives are graded by evidence, not by being written down. Each objective lists the
artifact that would demonstrate it. An objective with no linked artifact is not achieved.

| ID | Objective | Demonstrated by |
| --- | --- | --- |
| OBJ-1 | Establish a defensible, reproducible scientific foundation for XRL-IDARS | `docs/phase1/`, `REPRODUCIBILITY.md` |
| OBJ-2 | Detect malicious flow behaviour with documented, testable evidence | `results/baselines/` |
| OBJ-3 | Quantify the marginal value of temporal modelling | RQ2 experiments |
| OBJ-4 | Establish whether fusion is justified rather than assumed | RQ3 experiments + calibration report |
| OBJ-5 | Make every feature mathematically defined and provenance-tracked | `docs/phase1/FEATURE_DEFINITIONS.md` |
| OBJ-6 | Separate research-only features from live-reproducible features | `docs/phase1/FEATURE_COMPATIBILITY.md` |
| OBJ-7 | Expose and quantify domain shift rather than hide it | six cross-dataset directions + OOD |
| OBJ-8 | Explain predictions at model-attribution level, with stated limits | `results/shap/` |
| OBJ-9 | Turn detector output into a comparable, baseline-tested response policy | `results/dqn/` |
| OBJ-10 | Demonstrate that live feature extraction matches training-time features | `results/realtime/feature_parity.csv` |
| OBJ-11 | Guarantee safe autonomous response through a gated safety layer | `docs/phase3/`, `configs/safety/` |
| OBJ-12 | Make the system auditable end-to-end (predictions, actions, rollbacks) | audit log + replay |
| OBJ-13 | Answer "what happens when it fails?" for every component | `docs/failures/`, failure injection tests |
| OBJ-14 | Be honest about limitations and unresolved questions | `docs/viva/`, final report |

## Success criterion

Success is **not** a high accuracy number. Success is that an external reader can:

1. reconstruct any number from artifacts, config, code and commit;
2. understand why each decision was made, including trade-offs;
3. identify exactly when and how the system fails.

See §96 of the build spec: the project is `DATA + METHOD + MODEL + EVIDENCE + EXPLANATION +
SYSTEM + SAFETY + LIMITATIONS`.
