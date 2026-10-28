# XRL-IDARS — Verification Addendum & CI Closure Report

**Date:** 2026-10-28  
**Baseline Git Revision Tested:** `fbb375b07f2953c9ebfed14030d28b1013a17272`  
**Target Git Ref / Branch:** `main`  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Predecessor Verification Bundle:** [`results/verification/FINAL-CLOSURE-20261028-205800/`](file:///home/rishikesh/Desktop/fyp-xrlids/results/verification/FINAL-CLOSURE-20261028-205800/)

---

## 1. Executive Summary & CI Diagnostic Root Cause

GitHub Actions run [`40717175269`](https://github.com/rishikeshgowdakk/fyp-xrlids/actions/runs/40717175269) on commit `fbb375b07f2953c9ebfed14030d28b1013a17272` failed across two distinct root causes:

1. **Python 3.11 Incompatibility (Upstream Dependency Requirements):**
   - In `requirements.txt` and `pyproject.toml`, dependencies are pinned to modern 2026 production releases: `numpy==2.5.3`, `scipy==1.18.1`, and `shap==0.52.0`.
   - Inspection of PyPI release metadata reveals that `numpy==2.5.3`, `scipy==1.18.1`, and `shap==0.52.0` specify `requires_python: >=3.12` and provide binary wheels solely for Python 3.12, 3.13, 3.14, and 3.15 (no Python 3.11 wheels or source compatibility).
   - Python 3.10 and 3.11 cannot resolve `numpy==2.5.3`. The project configuration `requires-python = ">=3.10"` was overly broad given these frozen dependencies.
   - **Resolution:** `pyproject.toml` and `README.md` are aligned to `requires-python = ">=3.12"`, preserving model checkpoint compatibility and avoiding blind dependency downgrades. The CI test matrix is focused on Python 3.12.

2. **Python 3.12 Package Installation Defect:**
   - On Python 3.12, all 10 dependency packages installed successfully in 25 seconds.
   - However, `.github/workflows/ci.yml` executed:
     ```bash
     pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt || pip install -e .[dev]
     ```
   - Because `pip install -r requirements.txt` succeeded with exit code 0, the fallback `|| pip install -e .[dev]` was never evaluated. Consequently, the local `xrlids` package from `src/` was never installed into the Python virtual environment.
   - When `pytest tests/` was invoked, `tests/conftest.py` failed during collection with `ModuleNotFoundError: No module named 'xrlids'`.
   - **Resolution:** Replaced the conditional command with a single deterministic installation command:
     ```bash
     pip install --extra-index-url https://download.pytorch.org/whl/cpu -e .[dev]
     ```
     This installs the `xrlids` package in editable mode along with all pinned runtime and dev dependencies (`pytest==9.1.1`). Added `import xrlids` to pre-test verification step.

---

## 2. Test-Tier Arithmetic Reconciliation (481 Tests Total)

An apparent discrepancy was noted where $434 + 18 + 14 = 466 \ne 481$. The physical pytest collection across all test directories derives the exact test inventory:

| Suite Directory | Number of Collected Tests | Category Breakdown |
|:---|:---:|:---|
| `tests/unit/` | **387** | 15 working-tree clean regression tests + 372 unit tests |
| `tests/data/` | **45** | 32 pure schema/column tests + 13 physical dataset tests |
| `tests/integration/` | **31** | 30 pure pipeline/safety tests + 1 physical dataset replay test |
| `tests/model/` | **18** | 18 canonical model checkpoint & inference tests |
| **Total Full Repository** | **481** | **481 collected tests** |

### Complete Reconciliation of the 4 Tiers:

- **Tier 1 (Focused Working-Tree Semantics):** **15 tests** (`tests/unit/test_working_tree_clean.py`).
- **Tier 2 (Data-Independent Logic Suite):** **434 tests** ($372 \text{ remaining unit} + 32 \text{ data schema} + 30 \text{ integration} = 434$).
- **Tier 3 (Artifact-Backed Inference Suite):** **18 tests** (`tests/model/`).
- **Tier 4 (Dataset-Dependent Suite):** **14 tests** ($6 \text{ in } \texttt{test\_cicids2017\_real\_extraction.py} + 7 \text{ in } \texttt{test\_column\_contract\_datasets.py} + 1 \text{ in } \texttt{test\_multi\_file\_experiment.py}$).

$$\text{Total} = \underbrace{15}_{\text{Tier 1}} + \underbrace{434}_{\text{Tier 2}} + \underbrace{18}_{\text{Tier 3}} + \underbrace{14}_{\text{Tier 4}} = \mathbf{481}\text{ tests}$$

**Explanation of the 466 vs 481 discrepancy:**
The sum $434 + 18 + 14 = 466$ omitted Tier 1 (15 tests). Adding Tier 1 yields exactly $466 + 15 = 481$. Alternatively, grouping all data-independent tests together yields $449 \text{ tests}$ ($15 + 434$), which with Tier 3 (18) and Tier 4 (14) gives $449 + 18 + 14 = 481$.

### Clean-Checkout Execution Behavior:
- **When `data/raw/` is present (local lab environment):**
  - **481 passed**, 0 failed, 0 skipped in 46.40s. Exit code: `0`.
- **When `data/raw/` is absent (clean GitHub Actions clone without 30 GB raw dataset):**
  - **467 passed**, 0 failed, **14 cleanly skipped** with informative prerequisite notices. Exit code: `0`.

---

## 3. Exact Code and Configuration Changes

1. [`.github/workflows/ci.yml`](file:///home/rishikesh/Desktop/fyp-xrlids/.github/workflows/ci.yml):
   - Changed matrix to `python-version: ["3.12"]`.
   - Changed installation command to `pip install --extra-index-url https://download.pytorch.org/whl/cpu -e .[dev]`.
   - Added `import xrlids` to environment pre-test verification step.
2. [`pyproject.toml`](file:///home/rishikesh/Desktop/fyp-xrlids/pyproject.toml):
   - Aligned `requires-python = ">=3.12"` to match upstream requirements of `numpy==2.5.3`, `scipy==1.18.1`, and `shap==0.52.0`.
3. [`README.md`](file:///home/rishikesh/Desktop/fyp-xrlids/README.md):
   - Updated prerequisites to Python 3.12+ (tested on 3.14.4; verified on 3.12 in CI).
   - Updated installation instructions to `pip install -e .[dev]`.
4. [`results/verification/ADDENDUM-CI-VERIFICATION-20261028/`](file:///home/rishikesh/Desktop/fyp-xrlids/results/verification/ADDENDUM-CI-VERIFICATION-20261028/):
   - Recorded addendum report and machine-readable manifest.
