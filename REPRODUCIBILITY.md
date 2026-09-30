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

## 4. Dataset preparation - *blocked on manual download*

The historical primary mirror (`iscxdownloads.cs.unb.ca`) does not resolve from this
network (NXDOMAIN, verified 2026-09-30; general internet confirmed working via control
hosts). Download the files manually from the official pages, then:

```bash
# what is missing and where it goes:
.venv/bin/python scripts/phase1/prepare_dataset.py instructions

# after placing files in data/raw/<dataset>/:
.venv/bin/python scripts/phase1/prepare_dataset.py register --dataset <key> --all
.venv/bin/python scripts/phase1/prepare_dataset.py verify --dataset <key>
.venv/bin/python -m xrlids.cli verify-datasets
```

`register` computes each SHA256 from the actual bytes on disk - checksums cannot be
hand-entered. `verify` re-reads files and hard-fails on mismatch. A file that was never
downloaded stays `expected`; nothing is fabricated.

Checksum rule: a SHA256 mismatch is a hard failure. Datasets are never silently replaced.

## 5. Audit → splits → train → evaluate - *pending data*

```bash
.venv/bin/python scripts/phase1/03_run_audit.py                     # audit all acquired datasets
.venv/bin/python scripts/phase1/01_dataset_audit.py --dataset cicids2017 --input <file.csv>
.venv/bin/python scripts/phase1/02_build_splits.py  --dataset cicids2017 --rung R10 --input <file.csv>
.venv/bin/python scripts/phase1/feature_contract_evidence.py        # D-002 evidence
.venv/bin/python scripts/phase1/generate_reports.py
```

The audit runner validates every real file's header against the declared column maps
(`schema_status`), audits each file, records label-rejection accounting, and updates the
manifest honestly (`validated` only when validation actually passed).

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
