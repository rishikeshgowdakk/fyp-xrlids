# XRL-IDARS

**Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System**

XRL-IDARS is a research prototype for network-flow intrusion detection, explainability, and safety-constrained response decision support. It combines canonical bidirectional flow construction, deterministic security rules, a frozen binary detector, TreeSHAP explanations, a Dueling DQN response policy, and a deterministic safety gate.

> **Operational truth:** the documented live/replay detection path currently uses the registered Random Forest models. XGBoost is implemented and has a separate reported benchmark comparison, but it is not registered as the canonical live detector in `src/xrlids/models/registry.py`. Do not describe XGBoost as the live champion until its artifacts, preprocessing, registry integration, end-to-end tests, and benchmark provenance have been verified.

## Start here

| Document | What it covers |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Authoritative live/offline separation, data flow, and safety boundaries |
| [Model Selection](docs/MODEL_SELECTION.md) | Formal champion selections across all eight ML and RL categories |
| [Feature Engineering Study](docs/FEATURE_ENGINEERING_STUDY.md) | Empirical evaluation across five feature rungs (R4-R30) and three datasets |
| [XGBoost vs Random Forest](docs/RF_VS_XGBOOST.md) | Reconciled empirical cross-dataset comparison and latency analysis |
| [Implementation status](docs/IMPLEMENTATION_STATUS.md) | Subsystem implementation and verification status |
| [Model artifact audit](docs/MODEL_ARTIFACT_AUDIT.md) | Canonical model files, feature contracts, and provenance |
| [Evaluation protocol](docs/EVALUATION_PROTOCOL.md) | Dataset splits, metrics, and reproducibility requirements |
| [Explainability](docs/EXPLAINABILITY.md) | TreeSHAP scope and interpretation |
| [DQN response policy](docs/DQN_RESPONSE_POLICY.md) | Six-dimensional state and action policy |
| [Safety gate](docs/SAFETY_GATE.md) | Advisory defaults and response guardrails |
| [Flow processing](docs/FLOW_PROCESSING.md) | Bidirectional flow construction and feature extraction |
| [Latency evaluation](docs/LATENCY_EVALUATION.md) | Reported component and pipeline timings |
| [Exhibition guide](docs/EXHIBITION_GUIDE.md) | Existing demonstration instructions |

## Architecture at a glance

### Live / PCAP path

1. Capture or replay packets.
2. Parse supported packet headers; payload contents are not retained by the documented parser.
3. Build canonical bidirectional flows using the five-tuple.
4. Finalize flows on TCP FIN/RST or the configured idle timeout.
5. Validate the dataset-compatible R10 or R4 feature contract.
6. Evaluate deterministic rules independently from the ML posterior.
7. Run the registered Random Forest detector and obtain a binary benign/attack score.
8. Generate TreeSHAP explanations for supported tree-model predictions.
9. Pass response context to the Dueling DQN policy.
10. Apply deterministic safety checks and record the advisory decision.

The live model evaluates **completed flows**, not every in-flight packet. The architecture documentation specifies a 120-second idle timeout and TCP FIN/RST completion.

### Offline research path

The repository also preserves supervised LSTM and RF–LSTM score-fusion experiments for offline dataset evaluation. They are not part of the documented live inference path. XGBoost is a separate supervised candidate/evaluation track; it must not be conflated with the registered RF runtime path.

## Feature contracts

- **R10:** CIC-IDS2017 and CSE-CIC-IDS2018; ten canonical flow features.
- **R4:** UNSW-NB15; four derivable flow features.

The exact ordered feature definitions are maintained in `src/xrlids/features/definitions.py`. A model must be paired with its matching train-fitted preprocessor and feature contract. Never substitute a preprocessor from another dataset or silently fill missing features.

## Detection, explanation, and response are different jobs

- **Detection model:** estimates binary (P(ATTACK)); the canonical RF artifacts are binary classifiers.
- **TreeSHAP:** explains the selected tree detector's prediction. It does not explain the DQN policy.
- **DQN:** selects a response recommendation from its trained six-dimensional causal state.
- **Safety gate:** can reject or override unsafe recommendations.
- **Response execution:** the standard operating mode is advisory/dry-run. Do not claim that a recommendation changed firewall or kernel state unless an explicitly authorized isolated-lab execution and its verification are demonstrated.

Ground-truth attack-family labels in datasets are not automatically predictions from the binary detector.

## XGBoost status

The repository contains an `XGBoostDetector` wrapper with fit, prediction, feature-importance, and JSON model persistence methods. Unit tests cover basic fit/predict, input validation, feature importance, and save/load round trips.

The reported comparison document contains candidate metrics for CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15. Those figures are **reported results, not a substitute for a reproducible experiment**. In particular:
- The canonical model manifest currently lists RF, LSTM, DQN, and fusion artifacts; it does not list canonical XGBoost model artifacts.
- The canonical runtime registry currently registers RF models for the three benchmarks.
- The comparison and latency documents contain inconsistent timing figures; see [the comparison audit](docs/RF_VS_XGBOOST.md).
- The CSE-CIC-IDS2018 reported attack F1 is very low for both candidates. A small relative improvement does not establish a useful detector.
- Test-set results must not be used to select a production champion. Champion selection belongs on validation data, followed by one untouched final test evaluation.

Accordingly, XGBoost is documented as an **implemented candidate requiring artifact/provenance and integration verification**, not as the deployed live champion.

## Environment and tests

The current GitHub Actions workflow uses Python 3.12 and installs the project with its development extra:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install --extra-index-url https://download.pytorch.org/whl/cpu -e ".[dev]"
pytest tests/ -v -ra --tb=short
```

For packet capture on a real interface, operating-system permissions and interface availability may be required. PCAP replay is the safer reproducible path for demonstrations.

Check the [GitHub Actions history](https://github.com/rishikeshgowdakk/fyp-xrlids/actions) for the status of the exact commit you intend to use. A green run proves only the checks that actually ran; tests skipped because external raw datasets were unavailable are not empirical dataset validation.

## Research integrity rules

1. Keep train, validation, and test partitions separate.
2. Tune models and thresholds on validation data; use the test split once for final reporting.
3. Report each dataset separately because R10 and R4 are different contracts and populations.
4. Report precision, recall, F1, PR-AUC, ROC-AUC, false-positive rate, latency, and artifact size; do not rely on accuracy alone.
5. Record dataset version, source files, split manifest/hash, feature order, preprocessing artifact, model parameters, random seed, software versions, and artifact checksum.
6. Distinguish implemented, unit-tested, integration-tested, empirically reproduced, and operationally enabled features.
7. Never label a recommendation as an executed mitigation without execution and post-action verification evidence.

## Repository

[GitHub: rishikeshgowdakk/fyp-xrlids](https://github.com/rishikeshgowdakk/fyp-xrlids)
