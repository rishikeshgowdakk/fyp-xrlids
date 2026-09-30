# EXPERIMENT REGISTRY

Nothing important gets evaluated without an Experiment Card. This registry is the index of
every experiment and its status.

## ID convention

```text
EXP-<DATASET>-<FEATURESET>-<MODEL>-<NNN>
```

| Token | Values |
| --- | --- |
| DATASET | `CIC` · `CSE` · `UNSW` · `XFER` (cross-dataset) · `OOD` |
| FEATURESET | `R10` · `R15` · `R20` |
| MODEL | `RF` · `LSTM` · `FUSION` · `DQN` |
| NNN | zero-padded sequence |

Examples: `EXP-CIC-R20-FUSION-001`, `EXP-XFER-CIC2UNSW-RF-001`.

## Required companions

Every experiment must have, before it is considered complete:

1. an experiment card in this directory (from [`../templates/EXPERIMENT_CARD_TEMPLATE.md`](../templates/EXPERIMENT_CARD_TEMPLATE.md));
2. a machine-readable config under `configs/experiments/`;
3. result artifacts under `results/`;
4. any resulting claim registered in [`../03_DECISIONS/CLAIMS_REGISTRY.md`](../03_DECISIONS/CLAIMS_REGISTRY.md).

## Recorded experiments

_None yet._ No datasets have been acquired and no models trained, so no experiment has run.

| Experiment ID | RQ | Dataset(s) | Feature set | Model | Config | Result path | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | — | — |

Status values: `PLANNED` · `RUNNING` · `DONE` · `BLOCKED` · `ABANDONED`

---

## Planned experiment matrix (Phase 1)

### Primary matrix — 27 results (§36)

3 datasets × 3 feature sets × 3 model types.

| | R10 | R15 | R20 |
| --- | --- | --- | --- |
| **CICIDS2017** | RF / LSTM / Fusion | RF / LSTM / Fusion | RF / LSTM / Fusion |
| **CSE-CIC-IDS2018** | RF / LSTM / Fusion | RF / LSTM / Fusion | RF / LSTM / Fusion |
| **UNSW-NB15** | RF / LSTM / Fusion | RF / LSTM / Fusion | RF / LSTM / Fusion |

Status: **BLOCKED** on D-002 (feature rung definition) and D-004 (dataset acquisition).

### Cross-dataset matrix — 6 directions (§37)

CIC→CSE, CIC→UNSW, CSE→CIC, CSE→UNSW, UNSW→CIC, UNSW→CSE.
Each direction requires a "why did performance drop?" analysis (§38).
Status: **BLOCKED** on D-005.

### Additional experiments

| Experiment family | Purpose | Status |
| --- | --- | --- |
| Threshold sweep + trade-off curves | §31, §32 | BLOCKED on D-003 |
| Calibration (reliability, Brier, ECE) | §40 | BLOCKED on D-003 |
| OOD / unseen attack family | §39 | BLOCKED on D-004 |
| SHAP + stability | §41 | BLOCKED on D-002 |
| DQN reward sensitivity (A/B/C) | §51 | Phase 2 |
| DQN baseline comparison | §52 | Phase 2 |
| Live feature parity | §61 | Phase 3 |
| Traffic-burst experiment ("1000 packets") | §66, §90 | Phase 3 |
| Failure injection | §72 | Phase 3 |
| Performance / latency profiling | §73 | Phase 3 |
