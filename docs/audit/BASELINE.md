# XRL-IDARS — Baseline Verification & Environment Audit

**Document Path:** `docs/audit/BASELINE.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Branch:** `main`  
**Current HEAD Commit:** `7d6bcd446b7d99bf5625173870bd0a7325eac467`  
**Remote `origin/main` Ref:** `7d6bcd446b7d99bf5625173870bd0a7325eac467` (Up to date with origin/main)  
**Working-Tree State:** Clean (zero uncommitted or untracked changes at baseline capture)

> **Historical snapshot:** This document records the suite at baseline commit `7d6bcd4` (481 tests). The current repository suite collects **493 tests**; see `docs/audit/FINAL_AUDIT_REPORT.md` for the current inventory.

---

## 1. Authoritative Git Baseline & Commit History

### Commit Details
- **HEAD SHA:** `7d6bcd446b7d99bf5625173870bd0a7325eac467`
- **Commit Message:** `fix(ci): align Python support to 3.12+, fix package installation in workflow, and add test arithmetic reconciliation addendum`
- **Author:** `rishikeshgowdakk <rishikeshgowdakk@gmail.com>`
- **Date:** `Wed Oct 28 21:28:15 2026 +0530`

### Recent Commits (Top 5 on `main`)
1. `7d6bcd4` — `fix(ci): align Python support to 3.12+, fix package installation in workflow, and add test arithmetic reconciliation addendum`
2. `fbb375b` — `feat: add GitHub Actions CI workflow and final verification closure reports`
3. `3c4b9d3` — `test: expand test_working_tree_clean suite with 15 comprehensive git status scenarios`
4. `3bb1cc0` — `docs: update git commit hashes in phase 1 reports`
5. `66eca9d` — `feat: add granular git working-tree status semantics and comprehensive unit tests`

---

## 2. GitHub Actions CI Run Audit

### Latest Remote CI Execution
- **Workflow:** `CI` (`.github/workflows/ci.yml`)
- **Run ID:** `40722881636`
- **Run URL:** [https://github.com/rishikeshgowdakk/fyp-xrlids/actions/runs/40722881636](https://github.com/rishikeshgowdakk/fyp-xrlids/actions/runs/40722881636)
- **Triggering Commit:** `7d6bcd446b7d99bf5625173870bd0a7325eac467`
- **Status:** `completed`
- **Conclusion:** `success`
- **Execution Time:** Created `2026-10-28T16:07:41Z`, Completed `2026-10-28T16:09:12Z` (Duration: 1m 31s)

### Individual Job Audit
| Job Name | Job ID | Matrix Version | Conclusion | Key Step Results |
|:---|:---:|:---:|:---:|:---|
| `Test Suite (Python 3.12)` | `122938234777` | Python 3.12 | `success` | Set up Python 3.12 (`success`)<br>Install package and dependencies (`success`, ~25s)<br>Verify Environment (`success`)<br>Run Core Test Suite (`success`, 467 passed, 14 skipped) |

---

## 3. Investigation of Previous CI Failures

The previous CI run on commit `fbb375b07f2953c9ebfed14030d28b1013a17272` (Run ID: [`40717175269`](https://github.com/rishikeshgowdakk/fyp-xrlids/actions/runs/40717175269)) failed on both Python 3.11 and Python 3.12. The forensic root causes and verified resolutions are:

### A. Python 3.11 Incompatibility: `numpy==2.5.3` Upstream Constraint
- **Symptom:** `pip install -r requirements.txt` failed with `ERROR: No matching distribution found for numpy==2.5.3`.
- **Root Cause Analysis:** 
  1. The project pinned dependencies in `requirements.txt` and `pyproject.toml` to modern 2026 production releases: `numpy==2.5.3`, `scipy==1.18.1`, `pandas==3.0.6`, and `shap==0.52.0`.
  2. Inspection of PyPI metadata via JSON API reveals that `numpy==2.5.3` specifies `requires_python: >=3.12`. Only binary wheels for `cp312`, `cp313`, `cp314`, and `cp315` are published. No Python 3.11 distribution exists on PyPI.
  3. Upstream NumPy, SciPy, and SHAP dropped Python 3.11 support. The specification `requires-python = ">=3.10"` in `pyproject.toml` was overly broad and contradicted the frozen dependency requirements.
- **Resolution:** `pyproject.toml` and `README.md` were updated to reflect `requires-python = ">=3.12"`. The CI matrix was aligned to `python-version: ["3.12"]`. This preserves canonical model weights without artificial downgrades.

### B. Python 3.12 Import Failure: Editable Package Installation
- **Symptom:** Dependencies installed cleanly, but `pytest tests/` failed during collection: `ModuleNotFoundError: No module named 'xrlids'` in `tests/conftest.py`.
- **Root Cause Analysis:**
  1. The workflow previously executed:
     ```bash
     pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt || pip install -e .[dev]
     ```
  2. Because `pip install -r requirements.txt` returned exit code 0 on Python 3.12, the shell short-circuited and did not execute the fallback `|| pip install -e .[dev]`.
  3. `requirements.txt` installs third-party libraries, but does not install the root `xrlids` package from `src/`.
  4. In the standard `src/` layout, `import xrlids` fails unless `src/` is in `PYTHONPATH` or the package is installed into `site-packages`.
- **Resolution:** Replaced the conditional command with a single deterministic installation command:
  ```bash
  pip install --extra-index-url https://download.pytorch.org/whl/cpu -e .[dev]
  ```
  Added explicit validation `python -c "import xrlids, torch, sklearn, shap; ..."` to fail early if packaging is defective.

---

## 4. Test Suite Inventory & Tier Breakdown

### Repository-Wide Test Collection (Pytest 9.1.1)
Total Collected Tests: **481 tests** across 4 test directories:
- `tests/unit/`: **387 tests**
- `tests/data/`: **45 tests**
- `tests/integration/`: **31 tests**
- `tests/model/`: **18 tests**

### 4-Tier Test Classification

| Tier | Category | Collected | Pass (Local) | Pass (CI Clean) | Skip (CI Clean) | Prerequisites |
|:---:|:---|:---:|:---:|:---:|:---:|:---|
| **Tier 1** | Focused Working-Tree Status Semantics | 15 | 15 | 15 | 0 | None (Mocked Git states in temp dirs) |
| **Tier 2** | Data-Independent Core Logic | 434 | 434 | 434 | 0 | None (In-memory structures, unit logic) |
| **Tier 3** | Artifact-Backed Model Inference | 18 | 18 | 18 | 0 | Canonical models committed under `models/` |
| **Tier 4** | Physical Dataset-Dependent Replay | 14 | 14 | 0 | 14 | Physical raw CSV files in `data/raw/` (~30 GB) |
| **Full** | **Total Repository Suite** | **481** | **481** | **467** | **14** | All checks pass with 0 failures |

### Test-Tier Arithmetic Reconciliation
$$\underbrace{15}_{\text{Tier 1}} + \underbrace{434}_{\text{Tier 2}} + \underbrace{18}_{\text{Tier 3}} + \underbrace{14}_{\text{Tier 4}} = \mathbf{481}\text{ tests}$$
- Historical discrepancy: The earlier expression $434 + 18 + 14 = 466$ omitted Tier 1 (15 tests in `tests/unit/test_working_tree_clean.py`). Including Tier 1 yields exactly 481 tests.
- By directory: $387 \text{ (unit)} + 45 \text{ (data)} + 31 \text{ (integration)} + 18 \text{ (model)} = \mathbf{481}\text{ tests}$.

---

## 5. Execution Baseline Results

### Local Environment (`.venv`)
- **Python Version:** `3.14.4` (Linux x86_64, CPU-only)
- **PyTorch:** `2.14.0+cpu`
- **Scikit-Learn:** `1.9.1`
- **NumPy:** `2.5.3`
- **SciPy:** `1.18.1`
- **SHAP:** `0.52.0`
- **Execution Command:** `.venv/bin/pytest tests/ -ra`
- **Result:** **481 passed**, 0 failed, 0 skipped, 13 warnings in 46.40s (Exit code: `0`).

### Clean-Checkout Simulation (Without Uncommitted `data/raw/`)
- **Execution Command:** `.venv/bin/pytest tests/ -ra` (with `data/raw` absent)
- **Result:** **467 passed**, 0 failed, **14 skipped**, 13 warnings in 44.12s (Exit code: `0`).
- **Skip Rationales:**
  - 6 tests in `tests/data/test_cicids2017_real_extraction.py` skipped: `CIC-IDS2017 raw files not present on this machine`.
  - 7 tests in `tests/data/test_column_contract_datasets.py` skipped: `no raw datasets present on this machine`.
  - 1 test in `tests/integration/test_multi_file_experiment.py` skipped: `physical raw CSV files for 'unsw_nb15' are not present in data/raw/`.

---

## 6. Baseline Findings & Identified Anomalies

1. **Test Count Hardcoding in Report Templates:**
   - `scripts/phase1/generate_reports.py` line 826 hardcodes `466 passing tests`.
   - `scripts/phase2/run_phase2b_readiness_audit.py` lines 379-380, 908, 1006 hardcode `466 tests`.
   - `PROJECT_STATUS.md` line 72 states `466 unit and integration tests passing`.
   - *Impact:* Running report generation or status checks displays 466 instead of the current 481 tests.

2. **802.1Q VLAN Tagging in Pure-Python PCAP Parser:**
   - In `src/xrlids/demo/pcap.py`, `parse_packet_bytes` checks `eth_type != 0x0800` directly at offset 12:14.
   - If incoming frames contain 802.1Q/802.1ad VLAN tags (`0x8100`, `0x88A8`, `0x9100`), the frame is treated as non-IPv4 and discarded, whereas `src/xrlids/live/devices.py` already supports VLAN headers.
   - *Remediation Planned:* Expand `parse_packet_bytes` to parse 802.1Q headers transparently.
