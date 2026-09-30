# Experiment Card — `<EXPERIMENT_ID>`

> Copy this file to `docs/experiments/<EXPERIMENT_ID>.md` and fill every field.
> A field with no value must be marked `N/A` with a reason — never left blank silently.

## Identity

| Field | Value |
| --- | --- |
| Experiment ID | `<EXP-...>` |
| Date | |
| Research question | `RQ<n>` |
| Hypothesis | |
| Author / agent run | |

## Data

| Field | Value |
| --- | --- |
| Dataset | |
| Dataset version | |
| Input files | |
| SHA256 | |
| Rejection accounting ref | |

## Features and preprocessing

| Field | Value |
| --- | --- |
| Feature version | |
| Features (rung) | |
| Feature list hash | |
| Preprocessing steps | |
| Scaler artifact + hash | |

## Split

| Field | Value |
| --- | --- |
| Split config | |
| Train | |
| Validation | |
| Test | |
| Leakage audit ref | |

## Model

| Field | Value |
| --- | --- |
| Model | |
| Hyperparameters | |
| Seed(s) | |
| Initialization / checkpoint | |
| Framework + version | |

## Decision point

| Field | Value |
| --- | --- |
| Threshold | |
| Selection method | |
| Selection population | |

## Metrics

| Metric | Value |
| --- | --- |
| Accuracy | |
| Precision | |
| Recall | |
| F1 | |
| Macro-F1 | |
| ROC-AUC | |
| PR-AUC | |

Confusion matrix:

```text
TN:    FP:
FN:    TP:
```

## Execution

| Field | Value |
| --- | --- |
| Runtime | |
| Hardware | |
| Peak memory | |

## Interpretation

| Field | Value |
| --- | --- |
| Result | |
| Interpretation | |
| Failure modes | |
| Unexpected findings | |
| Decision / follow-up | |

## Artifacts

| Field | Value |
| --- | --- |
| Code | |
| Config | |
| Predictions | |
| Plots | |
| Logs | |
| Git commit | |

## Reproduce with

```bash
# exact command(s)
```
