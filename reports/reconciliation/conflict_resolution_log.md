# XRL-IDARS — Merge Conflict Resolution Log

**Reconciliation Branch:** `integration/preserve-main-and-final`  
**Parent 1 (`main`):** `934cf62eb5503b260067688fa64e8ef6f5a49a94`  
**Parent 2 (`final-acceptance`):** `2ea850e3a9757980f458bf7284e865d59697a913`  
**Common Ancestor (Merge Base):** `6408f5e82c5dcd81bd356973a74eb109f233be9e`  
**Reconciliation Commit:** `7c2bacd4676d50ade1960a78e692d0d0ee8ae564`  

---

## Executive Summary

During the two-parent merge of `feature/final-acceptance-integration` into `integration/preserve-main-and-final`, exactly **14 files** experienced merge conflicts due to parallel development after commit `6408f5e`. Every conflict was resolved surgically without dropping functionality or overwriting research artifacts from either branch.

Zero conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) remain. All 658 collected tests execute and pass cleanly with 100% success.

---

## Detailed Conflict Resolution Records

### 1. `src/xrlids/capture/__init__.py`
- **Conflict Cause:** Divergent module exports. `main` added `ScapyCaptureService` and `scapy_packet_to_packet_info`, while `final-acceptance` added `CapturePermissionError`, `CaptureStats`, and `ScapyCaptureConfig`.
- **Resolution:** Reconciled `__all__` to export the superset of symbols from both sides:
  - `CapturePermissionError`
  - `CaptureStats`
  - `ScapyCaptureConfig`
  - `ScapyCaptureService`
  - `scapy_packet_to_packet_info`
- **Result:** Backward-compatible with both legacy generator scripts and threaded live capture daemons.

### 2. `src/xrlids/capture/scapy_service.py`
- **Conflict Cause:** Structural divergence in the capture engine. `main` implemented synchronous generator replay (`replay_pcap(path, max_packets)`) and privilege checks (`list_interfaces()`, `check_permissions()`), while `final-acceptance` implemented a background threading sniffer with non-blocking bounded queues (`ScapyCaptureConfig`, `start()`, `stop()`, `get_packet()`).
- **Resolution:** Unified class `ScapyCaptureService` supporting both paradigms:
  - Preserved `ScapyCaptureConfig` constructor with queue size and BPF filter configuration.
  - Implemented threaded asynchronous background sniffing with `is_running`, `start()`, `stop()`, `get_packet()`, and `stats`.
  - Implemented direct synchronous generator `replay_pcap()`.
  - Implemented dual privilege verification: `check_permissions()` (boolean) and `verify_permissions()` (tuple `(bool, str)`).
- **Result:** Passes both `tests/unit/test_scapy_capture.py` (5 tests) and `tests/integration/test_scapy_capture.py` (4 tests).

### 3. `src/xrlids/explainability/explainer.py`
- **Conflict Cause:** Model unwrapping and attribution dictionary format. `main` added recursive unwrap helper for `ModelManager`/Pipeline wrappers and formatted attributions with `shap_attribution`, while `final-acceptance` used `attribution` and `direction`.
- **Resolution:** Implemented recursive unwrap supporting raw estimators, `ModelManager`, scikit-learn Pipelines, and `XGBoostDetector`. Emitted attribution dictionaries containing both legacy and newer keys (`shap_attribution`, `attribution`, `direction`), ensuring complete compatibility across all callers.
- **Result:** Passes `tests/unit/test_explainer.py` and `tests/unit/test_flow_treeshap.py`.

### 4. `src/xrlids/models/manager.py`
- **Conflict Cause:** Operational model selection. `main` introduced dynamic model selection between Random Forest and XGBoost with `force_model_type`, while `final-acceptance` enforced Random Forest as the sole certified operational detector.
- **Resolution:** Set default operational model explicitly to Random Forest (`model_name = "Random Forest (Sole Operational Detector)"`). Retained conditional import and support for `XGBoostDetector` if explicitly requested via `force_model_type="xgboost"`, strictly isolating it from the default live execution path.
- **Result:** Passes all model registry and pipeline tests.

### 5. `dashboard/streamlit_app.py`
- **Conflict Cause:** Sidebar system status and perception tier architecture description. `main` displayed "XGBoost Champion / RF", while `final-acceptance` displayed "Random Forest (Sole Operational Detector)".
- **Resolution:** Reconciled sidebar to state `Random Forest (Sole Operational Detector)`, R10 Canonical contract, and Advisory (Dry-Run) mode. Reconciled tier 1 description to clearly state Random Forest as the sole operational detector, while noting the XGBoost benchmark candidate from offline research.
- **Result:** All dashboard UI components render cleanly.

### 6. `dashboard/pages/01_Overview.py`
- **Conflict Cause:** Subsystem pipeline description, model provenance, and latency matrix.
- **Resolution:** 
  - Updated stage 2 to identify Random Forest as primary operational detector.
  - Reconciled model provenance list into "Random Forest (Operational Classifier)", "Offline Research Sequence & Candidate Models" (XGBoost JSON candidate and PyTorch LSTM `EXP-P2-LSTM-VALID-001`), and "DQN Response Policy".
  - Reconciled subsystem table to list Random Forest with $< 0.8$ ms latency and TreeSHAP with $8\text{--}27$ ms latency.
- **Result:** 100% consistent with operational architecture.

### 7. `dashboard/pages/02_Live_Ingestion.py`
- **Conflict Cause:** Ingestion modes. `main` had 2 modes (`PCAP File Replay` and `Live Interface Sniffing`), while `final-acceptance` added `Sample Traffic Generator (Demo)` with in-memory calibrated Scapy scenarios.
- **Resolution:** Adopted the full 3-mode interface from `final-acceptance`:
  1. `Live Interface Sniffing (Scapy)`
  2. `PCAP File Replay` (with threaded bounded queue `ScapyCaptureConfig`)
  3. `Sample Traffic Generator (Demo)` (calibrated Scapy attack scenarios)
- **Result:** Complete ingestion flexibility for all demonstration environments.

### 8. `dashboard/pages/03_Model_Evaluation.py`
- **Conflict Cause:** KPI row and comparison table column naming. `main` labeled columns "Random Forest Baseline" and "XGBoost Candidate", while `final-acceptance` labeled them "Random Forest (Operational)" and "Research Candidate (XGBoost)".
- **Resolution:** Reconciled KPI cards to report Random Forest operational metrics (F1: 0.9512, Latency: 0.80 ms). Formatted comparison table with clear operational vs. research distinctions: "Random Forest (Operational)", "Research Candidate (XGBoost)", "Delta", and "Status" (CERTIFIED OPERATIONAL).
- **Result:** Preserves empirical XGBoost comparisons while preventing false operational claims.

### 9. `dashboard/pages/08_System_Telemetry.py`
- **Conflict Cause:** Latency waterfall chart perception stage name and median timing. `main` had "2. Perception ML (XGBoost)" (0.690 ms), while `final-acceptance` had "2. Perception ML (Random Forest)" (0.120 ms).
- **Resolution:** Reconciled waterfall chart to display "2. Perception ML (Random Forest)" with 0.120 ms median latency.
- **Result:** Accurately reflects operational Random Forest latency profile.

### 10. `reports/generated/phase1_final_report.md`
- **Conflict Cause:** Generated commit hash divergence (`c7fe2f1` vs `48b8f7c`).
- **Resolution:** Reconciled to cite `48b8f7cc5c5597286ff8e0cdad43825fa9b56d73` with Phase 1 baseline `c7fe2f1a3f82c85f6d227b861169a0a2960f3bb2`.
- **Result:** Retains full audit traceability.

### 11. `reports/generated/phase1_status.md`
- **Conflict Cause:** Generated commit hash divergence (`c7fe2f1` vs `48b8f7c`).
- **Resolution:** Reconciled commit reference citing both acceptance commit and baseline.
- **Result:** Consistent with generated report metadata.

### 12. `docs/TEST_REPORT.md`
- **Conflict Cause:** Discrepant test counts (616 on `main` vs 585 on `theme-ui`/`final-acceptance`), differing test suite breakdowns, and verification sections.
- **Resolution:**
  - Authored authoritative milestone reconciliation table detailing the exact historical evolution: 493 -> 560 -> 573 -> 584 -> 585 -> 605 -> 608 -> 623 -> 658 tests.
  - Unified all test breakdowns (Phases 1-13 active pipeline, semantic invariants, live capture integration, flagship, CSV evaluation, Phase 2A baselines, 10k Replay Lab, and full regression).
  - Preserved all empirical microbenchmarks and cryptographic hash verification tables.
- **Result:** Authoritative, empirically grounded test documentation.

### 13. `docs/IMPLEMENTATION_STATUS.md`
- **Conflict Cause:** Architecture summary and scorecard differences. `main` had 17-component scorecard and empirical XGBoost comparison table, while `final-acceptance` had 21-component scorecard, approved operational architecture rules, and research benchmark preservation mandates.
- **Resolution:**
  - Formally stated approved operational pipeline and explicit preservation mandates.
  - Unified component scorecard across all 21 subsystems (COMP-01 through COMP-21).
  - Preserved multi-dataset XGBoost vs Random Forest empirical summary table across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15.
  - Preserved subsystem latency profile and architectural boundaries.
- **Result:** Complete master scorecard covering all capabilities.

### 14. `README.md`
- **Conflict Cause:** Divergent project headers, badges, architecture descriptions, and quick-start instructions.
- **Resolution:**
  - Reconciled title and badges (658 Passed, Python 3.12 | 3.14, RF Operational + TreeSHAP + DQN Advisory).
  - Added Operational Truth & Baseline callout.
  - Unified Quick Start guide (clone, install, pytest, launch Streamlit/Demo server, run calibrated Scapy simulations, and integrated pipeline demo).
  - Added full Mermaid operational architecture diagram.
  - Preserved verified model performance summary table.
  - Linked Research & Viva Documentation Hub and research integrity guidelines.
- **Result:** Single authoritative README reflecting the reconciled system.

---

## Pytest Configuration Update (`pyproject.toml`)
- **Root Cause of Test Collection Collision:** `main` contained `tests/integration/test_scapy_capture.py` (4 tests), while `final-acceptance` contained `tests/unit/test_scapy_capture.py` (5 tests). Due to identical module basenames, standard pytest import mode caused an `import file mismatch` error.
- **Fix:** Added `--import-mode=importlib` to `tool.pytest.ini_options.addopts` in `pyproject.toml`.
- **Result:** Allows pytest to import identically-named test modules across unit and integration directories concurrently, enabling clean collection and pass across all 658 tests.
