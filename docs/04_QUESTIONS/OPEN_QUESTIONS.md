# OPEN QUESTIONS

Questions raised by the project, the historical work, or the professor that are not yet
answered. Each links to a Decision ID if it blocks work, or an RQ if it is an experiment target.

| ID | Question | Type | Links | Status |
| --- | --- | --- | --- | --- |
| Q-001 | Are the historical R10/R15/R20 rungs scientifically defensible, or must they be re-derived? | research decision | D-002, RQ4 | OPEN |
| Q-002 | Is maximum F1 the right operational objective for an IDS threshold? | research decision | D-003 | OPEN |
| Q-003 | Which datasets and mirrors, and under what storage budget? | logistics decision | D-004 | OPEN |
| Q-004 | Should cross-dataset experiments align distributions or expose raw shift? | research decision | D-005, RQ5 | OPEN |
| Q-005 | What flow-completion policy is defensible for live capture? | research decision | D-006, RQ8 | OPEN |
| Q-006 | Are attack labels across the three datasets genuinely equivalent, and where do taxonomies diverge? | research question | §17, RQ5 | OPEN |
| Q-007 | Can rate-like features with infinite values be recomputed from source quantities rather than dropped? | data question | §14 | OPEN |
| Q-008 | Does duplicate removal in CICIDS2017 bias class balance? | data question | A-006 | OPEN |
| Q-009 | Is binary classification sufficient, or should attack-family classification be a secondary analysis? | research decision | §81 Checkpoint 2 | OPEN |
| Q-010 | Are RF and LSTM scores comparably calibrated enough for averaging to be justified? | research question | RQ3, A-003 | OPEN |
| Q-011 | Does a 0.90 model score correspond to roughly 90% empirical event frequency? | research question | §40, RQ?/calibration | OPEN |
| Q-012 | Is the historical DQN reward function appropriate, or is it value-laden? | research decision | §51 | OPEN |
| Q-013 | Does packet volume alone get misread as maliciousness ("1000 packets from one click")? | professor question | §66, §90 | OPEN |
| Q-014 | What is an acceptable false-positive rate for autonomous blocking in a campus network? | policy question | D-003, Phase 3 | OPEN |
| Q-015 | Can a sequence accidentally cross a split boundary, and how is that prevented and proven? | methodology question | §27, FR-014 | OPEN |
| Q-016 | How much of an observed cross-dataset drop is distribution shift vs schema incompatibility vs label mismatch? | research question | §38, RQ5 | OPEN |

## Rules

- An OPEN research question is not answered by the agent alone.
- If an experiment answers a question, the answer is recorded as a claim in
  [`../03_DECISIONS/CLAIMS_REGISTRY.md`](../03_DECISIONS/CLAIMS_REGISTRY.md) or a decision in
  [`../03_DECISIONS/DECISION_LOG.md`](../03_DECISIONS/DECISION_LOG.md).
