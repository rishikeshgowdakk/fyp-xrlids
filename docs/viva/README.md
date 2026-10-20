# VIVA / PROFESSOR DOCUMENTATION

This directory must let someone interrogate the project at five levels.

| Level | Question | Answered by |
| --- | --- | --- |
| 1 — What? | What does the system do? | `01_PROJECT_OBJECTIVE.md` |
| 2 — How? | How do RF/LSTM/Fusion/DQN work? | docs 04–08 |
| 3 — Why? | Why these features/datasets/split/model/Reward? | decisions + feature docs |
| 4 — Evidence? | How do you know it works? Show the test set and confusion matrix. | experiment cards + results |
| 5 — Failure? | When does it fail? What if the model is wrong or the API crashes? | `FINAL_VIVA_GUIDE.md` §9, `../failures/` |

## Consolidated Q&A map

The original plan proposed ten separate topic files. They are consolidated into
`FINAL_VIVA_GUIDE.md` and the linked evidence documents; separate files are not maintained, to
avoid duplicated or stale answers. Each topic below has a short answer, technical answer, evidence,
and the relevant experiment.

| Topic | Covered in |
| --- | --- |
| Project objective | `FINAL_VIVA_GUIDE.md` §1 |
| Datasets | `FINAL_VIVA_GUIDE.md` §2 |
| Features / R10 contract | `FINAL_VIVA_GUIDE.md` §2; `../HOW_IT_WORKS.md` |
| Random Forest | `FINAL_VIVA_GUIDE.md` §3 |
| LSTM | `FINAL_VIVA_GUIDE.md` §3 |
| Fusion | `FINAL_VIVA_GUIDE.md` §3 |
| SHAP | `FINAL_VIVA_GUIDE.md` §6 |
| DQN / autonomous response | `FINAL_VIVA_GUIDE.md` §5 and §8 |
| Live system | `FINAL_VIVA_GUIDE.md` §7; `DEMO_AND_VIDEO_SCRIPT.md` |
| Limitations | `FINAL_VIVA_GUIDE.md` §9; `../failures/` |
| Traffic burst case | `TRAFFIC_BURST_CASE.md` (executed; `../phase3/PHASE3E_BURST_REPORT.md`) |

## Ground rules for answers

- Answers cite evidence, not memory. If evidence does not exist, the answer is "not yet
  established" — not a plausible-sounding claim.
- Attribution ≠ causality: SHAP answers are framed as attribution.
- Live results are framed as "predictions generated", never "accuracy", absent ground truth.

## Practical demo material

| Document | Purpose |
| --- | --- |
| [`FINAL_VIVA_GUIDE.md`](FINAL_VIVA_GUIDE.md) | Full research/defense Q&A (datasets, models, RL, SHAP, rollback) |
| [`DEMO_AND_VIDEO_SCRIPT.md`](DEMO_AND_VIDEO_SCRIPT.md) | Readiness verdict, click-by-click demo runbook (3/7/12 min), viva supplement, video shot list + narration, recovery playbook, cheat sheet |
| [`../HOW_IT_WORKS.md`](../HOW_IT_WORKS.md) | End-to-end system explanation (simple + detailed) |
