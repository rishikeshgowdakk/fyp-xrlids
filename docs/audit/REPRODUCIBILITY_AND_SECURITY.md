# XRL-IDARS — Reproducibility, Security & Hygiene Audit

**Document Path:** `docs/audit/REPRODUCIBILITY_AND_SECURITY.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Status:** Complete Security Scanning, Dependency & Artifact Hygiene Audit

---

## 1. Secret Scanning & Credential Exposure

Automated recursive regex scanning was executed across the entire repository tree targeting API keys, private keys (`*.pem`, `*.key`), credentials, passwords, and authorization tokens:
- **Findings:** **Zero real credentials, private keys, or cloud secrets discovered.**
- The only token-related occurrences are:
  - Synthetic dummy keys (`XRLIDARS_LAB_SECRET_KEY`) utilized in `tests/unit/test_phase3_gate.py` for testing HMAC token verification in mock lab activation.
  - String parsing variables named `token` in label normalization (`src/xrlids/labels/contract.py`) and BPF filter tokenization (`src/xrlids/live/capture.py`).

---

## 2. Artifact Tracking, Git LFS & Size Compliance

1. **GitHub Size Invariants:**
   - Maximum single tracked file in Git: `models/rf/random_forest_cse2018.joblib` (66 MB), well under GitHub's 100 MB hard limit.
   - All 9 canonical model files and preprocessors are tracked directly in Git via explicit `.gitignore` unignore rules.
   - No Git LFS extension is required; ordinary `git clone` retrieves the entire operational system, code, and trained models ready for execution.
2. **Exclusion of Massive Raw Datasets:**
   - Raw benchmark files (~30 GB across 20 CSV files) are excluded by `.gitignore` (`data/raw/*`, `data/interim/*`, `data/processed/*`).
   - Checksums and provenance for all raw files are maintained in `data/manifests/dataset_registry.yaml`.
   - Temporary outputs, logs, virtual environments, and `.pytest_cache/` are comprehensively ignored.

---

## 3. Dependency Pinning & Packaging Hygiene

### A. Python Environment Compatibility
- **Configured Constraint:** `requires-python = ">=3.12"` in `pyproject.toml`.
- **Reason:** Pinned upstream dependencies `numpy==2.5.3`, `scipy==1.18.1`, and `shap==0.52.0` specify `requires_python: >=3.12`. Python 3.10 and 3.11 are strictly unsupported by these modern releases.
- **CI Matrix:** Focused on Python 3.12 on `ubuntu-latest`.
- **Deterministic Installation:** `pip install --extra-index-url https://download.pytorch.org/whl/cpu -e .[dev]` installs both the project package in editable mode and all pinned test dependencies in a single step.

### B. Pinning Discipline
All 10 dependencies in `requirements.txt` and `pyproject.toml` are pinned to exact versions for complete reproducibility:
- `numpy==2.5.3`
- `pandas==3.0.6`
- `scikit-learn==1.9.1`
- `scipy==1.18.1`
- `PyYAML==6.0.3`
- `joblib==1.6.0`
- `torch==2.14.0` (CPU-only index)
- `shap==0.52.0`
- `matplotlib==3.11.2`
- `pytest==9.1.1`

---

## 4. Reproducibility & Seeding Invariants

1. **Deterministic Seeding:**
   - Global seeding is enforced across Python `random`, `numpy.random`, and `torch.manual_seed` via `src/xrlids/utils/seeding.py::seed_everything(seed=42)`.
   - Random Forest models explicitly set `random_state=42`.
2. **Environment Fingerprinting:**
   - `src/xrlids/utils/env.py::environment_fingerprint()` captures operating system, Python minor version, CPU architecture, Git commit SHA, and exact installed package versions in all generated experiment manifests.
3. **Artifact Immutability:**
   - Frozen benchmark directories under `results/experiments/` are treated as immutable scientific evidence and are never overwritten during demonstration runs or CSV evaluation.
