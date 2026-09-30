# CLAIMS REGISTRY

Every major project claim gets a unique ID, linked evidence, and a status. This exists to
prevent accidental unsupported claims. If a claim has no evidence path, its status is Pending.

Status values: `VERIFIED` · `NOT REPRODUCED` · `PENDING` · `RETIRED`

## Format

```text
CLAIM-00X
"<claim text>"
Research question: RQ<n>
Evidence: EXP-<...> / results/<path>
Status: VERIFIED | NOT REPRODUCED | PENDING | RETIRED
Evidence path: <results/... / experiment card / commit>
Last checked: <date>
```

## Registered claims

_None yet._ This is intentional: the project has no datasets, no trained models and no
evaluation artifacts, so **no claim can currently be VERIFIED**. Claims are added as
experiments produce evidence.

| ID | Claim | RQ | Evidence | Status | Evidence path |
| --- | --- | --- | --- | --- | --- |
| — | *(registry empty at project start)* | — | — | — | — |

---

## Claims that must NOT be made yet

These are plausible-sounding statements that currently have **zero** support in this
repository. They must not appear in the README, reports or a demonstration until an
experiment card exists.

| Forbidden-until-proven claim | Why it is currently unsupported |
| --- | --- |
| "Fusion achieves N% accuracy." | No dataset acquired, no model trained, no test population defined. |
| "The system detects attacks in real time." | No live capture implemented; no parity check. |
| "LSTM improves detection over RF." | RQ2 not yet run on an aligned population. |
| "DQN outperforms fixed thresholds." | RQ7 not yet run; historical evidence was mixed. |
| "SHAP shows feature X causes detection." | Attribution is not causality (§41). |
| "Live accuracy is 100%." | Ground truth is unavailable live (§64). |
| "More features improve performance." | RQ4 exists precisely to test this (§20). |
| "The system is production-ready." | No performance profiling, no failure injection, no runbook. |

---

## Historical claims

Numbers reported by the previous XRL-IDARS repository are **not** registered here as claims.
They are quarantined in [`../04_QUESTIONS/HISTORICAL_RESULTS.md`](../04_QUESTIONS/HISTORICAL_RESULTS.md)
with status *historical — not reproduced*, and may only be converted into a claim after a
new experiment reproduces them.
