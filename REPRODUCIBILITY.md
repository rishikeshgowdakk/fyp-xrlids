# REPRODUCIBILITY

Goal: anyone cloning `xrlids-v1` can follow the sequence below and regenerate the
project's results from scratch.

> Status: **skeleton**. Exact commands are added as each stage is implemented.
> A stage listed here without a command is not yet reproducible and must not be
> cited as evidence.

---

## Required sequence

```text
environment setup
      ↓
dataset preparation        (acquire + checksum-verify)
      ↓
audit                      (scripts/phase1/01_dataset_audit.py)
      ↓
preprocessing              (cleaning + label contract)
      ↓
splits                     (scripts/phase1/02_build_splits.py + leakage audit)
      ↓
training                   (RF / LSTM / Fusion)
      ↓
evaluation                 (metrics, thresholding, calibration)
      ↓
result generation          (experiment JSON → reports)
```

---

## Environment

| Item | Value |
| --- | --- |
| Python | _TBD_ (pin on first dependency freeze) |
| Package manager | _TBD_ |
| OS tested for live capture | Linux (Scapy requires elevated capture privileges) |

Environment setup is **not yet pinned**. Pinning is tracked as a Phase 1 task; until
seeds, library versions and hardware are recorded, results are not fully reproducible.

---

## Determinism requirements

Every experiment must record, in its experiment card:

```text
random seed(s)
library versions (requirements lock / environment hash)
hardware (CPU/GPU model)
training wall-clock time
Git commit SHA
dataset file SHA256 values
feature-schema hash
preprocessor artifact hash
```

See the template at [`docs/templates/EXPERIMENT_CARD_TEMPLATE.md`](docs/templates/EXPERIMENT_CARD_TEMPLATE.md).

---

## Per-stage commands

### 1. Environment setup

```bash
# TODO: create and activate environment, install pinned dependencies
```

### 2. Dataset preparation

```bash
# TODO: download per data/manifests/dataset_registry.yaml and verify SHA256
```

Checksum rule: if a downloaded file's SHA256 does not match the registry, the
pipeline must **stop and report a mismatch**. Datasets are never silently replaced.

### 3. Audit

```bash
# TODO: python scripts/phase1/01_dataset_audit.py --config configs/datasets/<name>.yaml
```

### 4. Preprocessing and splits

```bash
# TODO: python scripts/phase1/02_build_splits.py --config configs/splits/splits.yaml
```

### 5. Training

```bash
# TODO: RF / LSTM / Fusion entrypoints
```

### 6. Evaluation and reporting

```bash
# TODO: python scripts/reporting/<generator>.py
```

---

## Reproducing a single claim

Given a claim ID from [`docs/03_DECISIONS/CLAIMS_REGISTRY.md`](docs/03_DECISIONS/CLAIMS_REGISTRY.md):

1. Find the linked experiment ID in [`docs/experiments/EXPERIMENT_REGISTRY.md`](docs/experiments/EXPERIMENT_REGISTRY.md).
2. Open the experiment card and read its config, seed, and Git commit.
3. Check out that commit and run the documented command.
4. Compare the regenerated result artifact against the committed artifact.

If any step is missing, the claim's status must be downgraded to *Pending*.
