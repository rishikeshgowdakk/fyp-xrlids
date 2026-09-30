# REPRODUCIBILITY

Goal: anyone cloning `fyp-xrlids` can set up the environment, acquire the documented
datasets, run the documented commands and regenerate the results.

> Status: **environment pinned and reproducible. Datasets not yet acquired, so the empirical
> stages currently report `DATA_NOT_AVAILABLE`.** Anything below marked *pending data* has not
> been run against real data and must not be cited as a result.

---

## 1. Environment setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .            # optional: editable install of the package
```

| Item | Value |
| --- | --- |
| Python | 3.14.4 |
| Platform verified | Linux x86_64, CPU-only |
| numpy | 2.5.3 |
| pandas | 3.0.6 |
| scikit-learn | 1.9.1 |
| scipy | 1.18.1 |
| torch | 2.14.0 (CPU) |
| shap | 0.52.0 |
| matplotlib | 3.11.2 |
| PyYAML | 6.0.3 |

Verify with:

```bash
.venv/bin/python -m xrlids.cli info
```

## 2. Tests (no datasets required)

```bash
.venv/bin/python -m pytest -q
```

Expected: 67 passed. Tests use tiny deterministic fixtures only.

## 3. End-to-end execution check (no datasets required)

```bash
.venv/bin/python -m xrlids.cli smoke --rung R10 --rows 1500
```

Writes `results/smoke/smoke_R10.json`. **This is a plumbing check on synthetic fixtures and is
labelled `SMOKE_ONLY`; it is not evidence.**

## 4. Dataset preparation — *pending data*

```bash
# 1. place each dataset file, then record its path + SHA256 in data/manifests/dataset_registry.yaml
# 2. verify integrity
.venv/bin/python -m xrlids.cli verify-datasets
```

Checksum rule: a SHA256 mismatch is a hard failure. Datasets are never silently replaced.

## 5. Audit → splits → train → evaluate — *pending data*

```bash
.venv/bin/python scripts/phase1/01_dataset_audit.py --dataset cicids2017 --input <file.csv>
.venv/bin/python scripts/phase1/02_build_splits.py  --dataset cicids2017 --rung R10 --input <file.csv>
.venv/bin/python scripts/phase1/generate_reports.py
```

## 6. Regenerating documentation from results

```bash
.venv/bin/python scripts/phase1/generate_reports.py
```

Writes `reports/generated/*.md` from the feature registry, the metrics module and result JSON.
Final metrics are never hand-typed into Markdown.

---

## Determinism record

Every experiment artifact records: experiment id, Git commit, dataset SHA-256, feature-schema
hash, seed, timestamp, software environment and artifact version. Seeds are applied to Python,
NumPy and PyTorch. Where full determinism is impossible (GPU kernels), the source of
nondeterminism must be recorded rather than hidden; phase 1 runs on CPU.

## Tracing a single claim

1. Find the experiment in `docs/experiments/EXPERIMENT_REGISTRY.md`.
2. Open its result JSON in `results/` and read the `metadata` block.
3. Check out the recorded Git commit and re-run the documented command.
4. Compare regenerated artifacts.

If any step is missing, the claim's status must be downgraded to *Pending*.
