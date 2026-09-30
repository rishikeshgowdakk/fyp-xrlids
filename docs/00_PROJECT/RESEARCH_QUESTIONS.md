# RESEARCH QUESTIONS

Status: **frozen** (RQ changes require a Decision ID per §9 — the agent must not silently change them)

These ten questions are the backbone of the repository. Every experiment must trace to at
least one RQ; every claim must cite the RQ it addresses.

| ID | Question | Primary phase | Primary evidence location |
| --- | --- | --- | --- |
| RQ1 | Can flow-level ML distinguish benign and malicious traffic? | 1 | `results/baselines/` |
| RQ2 | Does temporal information improve detection? | 1 | `results/baselines/` (RF vs LSTM) |
| RQ3 | Does RF + LSTM fusion outperform the individual models? | 1 | `results/baselines/`, `results/thresholding/` |
| RQ4 | Does adding more features consistently improve performance? | 1 | `results/feature_sweeps/` |
| RQ5 | How does the model behave under dataset / domain shift? | 1 | `results/cross_dataset/`, `results/ood/` |
| RQ6 | Which features drive predictions? | 1 | `results/shap/` |
| RQ7 | Can an RL policy select an appropriate response? | 2 | `results/dqn/` |
| RQ8 | Can the same feature contract be reproduced from live packets? | 3 | `results/realtime/` |
| RQ9 | What happens to performance when deployed on unseen network traffic? | 3 | `docs/phase3/` |
| RQ10 | Can autonomous response be executed safely in a controlled network? | 3 | `docs/phase3/`, `results/deployment/` |

---

## Question detail and intended methodology

### RQ1 — Flow-level separability
Train flow-level classifiers on each of the three datasets independently and evaluate on
held-out test splits. Report full confusion matrices and per-class metrics, not accuracy alone.

### RQ2 — Value of temporal information
Compare the supervised LSTM (sequences of T=5 flow vectors) against the RF baseline on the
same populations. Temporal advantage must be demonstrated on *aligned* populations, or the
comparison is invalid.

### RQ3 — Fusion benefit
Test whether mean-fused RF/LSTM scores beat both components. Requires that the two score
distributions are comparable (see calibration, §40). If fusion does not win, that is a valid,
reportable negative result.

### RQ4 — Feature-set size
Evaluate R10 / R15 / R20 across all three datasets and all three model types
(3 datasets × 3 feature sets × 3 models = 27 primary results). The historical finding that
"more features ≠ always better" is a **hypothesis to test**, not an assumption to inherit.

### RQ5 — Domain shift
Six transfer directions: CIC→CSE, CIC→UNSW, CSE→CIC, CSE→UNSW, UNSW→CIC, UNSW→CSE.
Plus OOD/unseen-attack-family evaluation where feasible.

### RQ6 — Attribution
SHAP on the tree model with documented explainer, sample size, background data and
aggregation. Attribution ≠ causality. Adds stability analysis across datasets / feature rungs / runs.

### RQ7 — Response policy
DQN over a state derived from detector scores (RF probability, LSTM score, fusion score)
with actions ALLOW / ALERT / BLOCK. Must be compared against naive baselines; the historical
result that DQN did not dominate every baseline is treated as an open question, not a fact.

### RQ8 — Live feature parity
Automated comparison of dataset-side vs Scapy-side feature calculation on the same synthetic
flow: per-feature absolute and relative difference against a documented tolerance.

### RQ9 — Unseen traffic
Replay vs live are reported separately. Live predictions are not "accuracy" without ground truth.

### RQ10 — Safe autonomous response
Controlled, isolated lab only, behind a safety layer, in OBSERVE → DRY-RUN → ENFORCE order.

---

## Rules tied to these questions

- The agent may implement the methodology but must not silently change a research question.
- If implementation reveals an RQ is impossible or flawed:
  `STOP → DOCUMENT PROBLEM → SHOW EVIDENCE → SHOW OPTIONS → SHOW CONSEQUENCES → ASK USER`.
