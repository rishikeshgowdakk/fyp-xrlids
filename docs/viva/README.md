# VIVA / PROFESSOR DOCUMENTATION

This directory must let someone interrogate the project at five levels.

| Level | Question | Answered by |
| --- | --- | --- |
| 1 — What? | What does the system do? | `01_PROJECT_OBJECTIVE.md` |
| 2 — How? | How do RF/LSTM/Fusion/DQN work? | docs 04–08 |
| 3 — Why? | Why these features/datasets/split/model/Reward? | decisions + feature docs |
| 4 — Evidence? | How do you know it works? Show the test set and confusion matrix. | experiment cards + results |
| 5 — Failure? | When does it fail? What if the model is wrong or the API crashes? | `10_LIMITATION_QUESTIONS.md`, `../failures/` |

## Required documents

Each question gets: **short answer · technical answer · evidence · relevant experiment**.

| Document | Status |
| --- | --- |
| `01_PROJECT_OBJECTIVE.md` | ⬜ |
| `02_DATASET_QUESTIONS.md` | ⬜ |
| `03_FEATURE_QUESTIONS.md` | ⬜ |
| `04_RF_QUESTIONS.md` | ⬜ |
| `05_LSTM_QUESTIONS.md` | ⬜ |
| `06_FUSION_QUESTIONS.md` | ⬜ |
| `07_SHAP_QUESTIONS.md` | ⬜ |
| `08_DQN_QUESTIONS.md` | ⬜ |
| `09_LIVE_SYSTEM_QUESTIONS.md` | ⬜ |
| `10_LIMITATION_QUESTIONS.md` | ⬜ |
| `TRAFFIC_BURST_CASE.md` | 🟡 skeleton |

## Ground rules for answers

- Answers cite evidence, not memory. If evidence does not exist, the answer is "not yet
  established" — not a plausible-sounding claim.
- Attribution ≠ causality: SHAP answers are framed as attribution.
- Live results are framed as "predictions generated", never "accuracy", absent ground truth.
