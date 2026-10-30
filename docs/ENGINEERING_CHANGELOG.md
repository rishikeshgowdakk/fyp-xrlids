# XRL-IDARS — Engineering Changelog

**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Standard:** Enterprise Security Engineering & Reproducible MLOps  

---

## [1.0.0] — 2026-10-30

### Added
- **5-Stage Autonomous Response Lifecycle:**
  - Implemented `ResponseExecutor` (`src/xrlids/response/executor.py`) managing the deterministic state transitions:
    `PROPOSED` $\to$ `AUTHORIZED` $\to$ `EXECUTED` $\to$ `VERIFIED` $\to$ `EXPIRED`/`ROLLED_BACK`.
  - Implemented `ResponseVerifier` (`src/xrlids/response/verification.py`) enforcing post-action host state verification and critical infrastructure immunity (`192.168.10.1`, `192.168.10.2`, `192.168.10.50`).
  - Implemented `ResponseOutcomeFeedbackLoop` (`src/xrlids/response/feedback.py`) logging causal transition tuples $(\mathbf{s}_t, a_t, r_t, \mathbf{s}_{t+1}, d_t)$ with multi-objective reward calculations for offline RL policy evaluation.
- **Multiclass Attack Family Attribution:**
  - Implemented `MulticlassAttackClassifier` (`src/xrlids/models/multiclass_detector.py`) classifying confirmed attacks into 6 canonical families: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`, `WEB_ATTACK`.
  - Added calibrated thresholding with fallback to `UNKNOWN` when maximum class probability $p^* < 0.40$, preventing forced misclassification of novel or stealth vectors.
  - Trained champion multiclass Random Forest on CICIDS2017 holdout partition achieving **95.52% weighted F1**. Saved artifact at `models/multiclass/multiclass_rf_champion.joblib` (2.4 MB).
- **Expanded Feature Studies ($R_4 \to R_{30}$):**
  - Evaluated feature ladder rungs $R_4$ (4 core features), $R_{10}$ (canonical 10 features), $R_{15}$, $R_{20}$, and $R_{30}$.
  - Documented empirical findings in `docs/FEATURE_ENGINEERING_STUDY.md` and cross-dataset feature availability in `docs/FEATURE_AVAILABILITY_MATRIX.md`.
- **Forensic Dataset Auditing:**
  - Completed forensic root-cause analysis of CSE-CIC-IDS2018 detection performance in `docs/datasets/CSE_CIC_IDS2018_AUDIT.md`.
  - Demonstrated that Day 1 Infiltration attacks exhibit 78%–98% statistical overlap with benign workstation browsing in $R_{10}$ flow features, while multi-day evaluations across DoS, DDoS, and Botnet traffic yield **>99.1% accuracy and >99.0% recall**.
- **Comprehensive Master Verification Matrix & Architecture Audit:**
  - Authored `docs/VERIFICATION_MATRIX.md` detailing implementation, testing, validation, and integration status for all 17 subsystems (COMP-01 through COMP-17).
  - Authored `docs/FINAL_DELIVERY_REPORT.md` and `docs/PERFORMANCE_REPORT.md`.
  - Added Decision Log entries **D-007** (Decoupled Multiclass Attribution) and **D-008** (5-Stage Action Lifecycle and Verified Rollback).

### Fixed & Remediated
- **Streamlit Command Center Remediation:**
  - `dashboard/pages/02_Live_Ingestion.py`: Fixed `CanonicalFlowBuilder(idle_timeout_s=120.0)` constructor argument mismatch; aligned `ScapyCaptureService()` instantiation and packet replay loop; wired direct flow ingestion into `pipeline.process_flow(f)`.
  - `src/xrlids/events/manager.py`: Added `get_all_events()` returning all buffered `SecurityEvent` objects from the thread-safe ring buffer.
  - `src/xrlids/capture/scapy_service.py`: Added `verify_permissions()` alias for raw socket capture checking.
  - `src/xrlids/flow/canonical_builder.py`: Added `flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port` accessors to `CanonicalFlowKey` and `features` property to `CanonicalFlow`.
  - `src/xrlids/tracking/source_tracker.py`: Added constructor argument aliases `window_seconds` and `escalation_threshold`, added properties, and added `reset()` and `is_in_cooldown()` methods.
  - `dashboard/pages/06_Source_Tracking.py`: Updated simulator to check `esc.escalate`, updated state table to inspect `tracker._records`.
  - `dashboard/pages/08_System_Telemetry.py`: Replaced missing `source_activity` with `source_escalated` and `source_status`; updated severity filters to support all levels (`NONE`, `INFORMATIONAL`, `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Verified all 8 dashboard pages via automated headless `AppTest` with **0 runtime exceptions**.
- **CI Workflow and Dependency Alignment:**
  - Pinned `scapy` and `xgboost` in `requirements.txt` and `pyproject.toml`.
  - Handled CI runner execution in `tests/integration/test_scapy_capture.py` when network interfaces are restricted.
  - Required provisioned raw dataset files in `tests/unit/test_replay_lab.py` to prevent false failures in minimal CI containers.
  - Preserved `_estimator_type = "classifier"` attribute on `XGBoostDetector` for scikit-learn metadata compatibility.

### Reconciled
- **Latency Benchmarks:**
  - Executed fresh CPU benchmark harness in `scripts/benchmark_latency_master.py` and updated `docs/LATENCY_EVALUATION.md`.
  - Reconciled timing differences across measurement scopes:
    - Feature schema validation: 3.938 ms
    - Single-model XGBoost inference: 0.223 ms
    - Single-model Random Forest inference: ~45 ms
    - Combined ModelManager inference (binary RF + multiclass RF): 92.78 ms
    - Rule engine: 0.0038 ms
    - Source tracker: 0.0028 ms
    - TreeSHAP local attribution: 49.49 ms
    - Dueling DQN policy: 0.175 ms
    - Deterministic Safety Gate: 0.0009 ms
    - Full Fast Path: 95.08 ms (with RF) / ~4.2 ms (with XGBoost)
    - Full Deep Path: 148.87 ms (with RF) / ~54.3 ms (with XGBoost)
- **Model Registry and Champion Status:**
  - Retained the three canonical Random Forest models (`models/rf/`) as the registered live/replay primary detectors in `models/registry/model_manifest.json` and `src/xrlids/models/registry.py`.
  - Preserved `XGBoostDetector` as an implemented candidate wrapper and research comparator with native JSON model persistence.
  - Documented that operational promotion of XGBoost requires validation-based tuning and explicit registry entries under Decision D-003 and D-007.

---

## [0.9.0] — 2026-10-29

### Added
- Canonical 10-feature flow contract ($R_{10}$) for CIC-IDS2017 and CSE-CIC-IDS2018.
- Canonical 4-feature flow contract ($R_4$) for UNSW-NB15.
- TreeSHAP local explainability module (`src/xrlids/explainability/explainer.py`).
- Deterministic protocol rule engine (`src/xrlids/rules/engine.py`).
- Multi-flow source activity tracker (`src/xrlids/tracking/source_tracker.py`).
- Dueling DQN response policy service (`src/xrlids/response/service.py`) on 6D state representation.
- Deterministic Safety Gate (`src/xrlids/response/safety.py`) with advisory defaults.
- Preserved historical supervised LSTM and score fusion baseline models.
