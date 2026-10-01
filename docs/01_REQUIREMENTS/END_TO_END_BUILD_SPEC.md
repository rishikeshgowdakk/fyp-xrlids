# END-TO-END BUILD SPECIFICATION — XRL-IDARS

Status: **authoritative** · Created: 2026-10-02 · Basis: [`../04_QUESTIONS/END_TO_END_SYSTEM_AUDIT.md`](../04_QUESTIONS/END_TO_END_SYSTEM_AUDIT.md)

This document specifies the **complete finished prototype** — one system spanning
`data → research methodology → trained detectors → explanation → response policy → safe
enforcement → live traffic → dashboard → evidence → reproducible documentation`. It is not a phase
plan; it is the definition of "finished".

**How to read it.** Every requirement has an ID (`BS-nnn`), a rationale, the evidence that will
prove it, where it is implemented, how it is validated, and an acceptance criterion that is either
true or false. A requirement with no falsifiable acceptance criterion is not a requirement.
Requirement statuses are tracked in the gap register at the end (`GAP-nn`), which is the single
authoritative list of remaining work.

---

## 1. System purpose

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-001 | The system detects benign vs malicious network flows from flow-level behavioural features and produces an explainable, calibrated risk score | defines the artifact being built | experiment records + metrics on all three datasets | `src/xrlids/` | §8 evaluation | three datasets each have a completed in-domain baseline with full metrics |
| BS-002 | The system converts detector output into a *response recommendation* (ALLOW/ALERT/BLOCK) through a policy, not a bare threshold | detection ≠ response; project thesis | policy evaluation vs baselines | `src/xrlids/rl/` (planned) | §12 | DQN beats or is honestly reported against all five baselines |
| BS-003 | Every automatic action passes a deterministic safety gate that cannot be bypassed | autonomous response without a guardrail is unsafe and indefensible | safety tests + audit log entries | `src/xrlids/safety/` (planned) | §14 | no BLOCK path exists in code that does not route through the gate |
| BS-004 | Every number in documentation is regenerable from committed artifacts | the project's own NFR-001 | report generator run in CI reproduces committed reports byte-for-byte | `scripts/phase1/generate_reports.py` | §21 | regenerating reports produces an empty `git diff` |
| BS-005 | Live traffic can be turned into the *same* feature vector the models were trained on | otherwise offline metrics are meaningless | parity report per feature | `src/xrlids/inference/` (planned) | §13 | `results/realtime/feature_parity.csv` shows every feature within tolerance |

## 2. System boundary

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-006 | In scope: flow classification, attribution, response recommendation, gated enforcement in an **owned lab** only | authority + honesty | scope doc | `docs/00_PROJECT/PROJECT_SCOPE.md` | review | scope unchanged; enforcement gated on authority statement |
| BS-007 | Out of scope: production IDS claims, identity attribution, content inspection, arbitrary networks | prevents overclaim | limitations doc | `docs/04_…` limitations (GAP-D01) | review | a `LIMITATIONS.md` lists each excluded claim |
| BS-008 | The three datasets are never merged into one training population | incompatible schemas/taxonomies | `merge_policy: forbid` enforced by a test | `data/manifests/dataset_registry.yaml` | unit test asserting no code path concatenates datasets | test fails if a pooled loader is introduced |
| BS-009 | Simulated/replayed/live results are labelled distinctly everywhere they appear | a demo must not pass simulation off as live | status token in every artifact | artifacts metadata | report lint | every result artifact carries `provenance.source ∈ {dataset_file, replay, live_capture, synthetic_fixture}` |

## 3. Functional requirements

The authoritative FR list stays in [`FUNCTIONAL_REQUIREMENTS.md`](FUNCTIONAL_REQUIREMENTS.md);
this spec adds only the FRs the finished system additionally needs:

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-010 | Multi-file dataset loading (all 8 CIC / all 10 CSE files as one auditable population, per-file provenance retained) | today's runner takes `existing_files[0]` only | dataset-load manifest listing every file+hash used | `src/xrlids/datasets/loading.py` | integration test with 3-file fixture | experiment record lists all input files with hashes |
| BS-011 | `require_verified_checksums`/`require_schema_validated` config keys are enforced or removed | configs currently lie | runner hard-fails on hash mismatch | `scripts/phase1/run_experiment.py` | failure-injection test with a corrupted file | run aborts with `CHECKSUM_MISMATCH` |
| BS-012 | Per-attack-family (multiclass) error analysis, even though the primary detector is binary | professor will ask "which attacks fail?" | family × error matrix | `src/xrlids/evaluation/error_analysis.py` | unit test | every experiment emits `per_family_metrics.csv` |
| BS-013 | Subsample runs are impossible to confuse with full runs in any human-facing surface | two of three committed experiments are subsamples | `PRELIMINARY_SUBSAMPLE` token in Markdown registry + report header | `scripts/phase1/generate_reports.py` | report lint | every report header states population size and sampling mode |

## 4. Dataset requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-014 | CIC-IDS2017 = official MachineLearningCSV distribution: 8 CSVs, 79 columns, 2,830,743 rows, 14 label values | benchmark identity | per-file row counts + label set in audit artifact | `data/raw/cicids2017/` | `03_run_audit.py` | audit matches the published counts exactly |
| BS-015 | CSE-CIC-IDS2018 = "Processed Traffic Data for ML Algorithms": 10 CSVs, 16,233,002 rows, 80 cols (84 for `Thuesday-20-02`) | benchmark identity | same | `data/raw/cse_cic_ids2018/` | audit | all 10 files audited; 84-col file handled explicitly |
| BS-016 | UNSW-NB15 = partitioned CSVs: training 175,341 / testing 82,332, 45 cols, `Normal` + 9 attack categories | benchmark identity; **manifest reference notes must be corrected** | audit + corrected manifest | `data/raw/unsw_nb15/`, `data/manifests/dataset_registry.yaml` | audit + doc review | manifest notes match the official UNSW page |
| BS-017 | Every file's SHA-256, byte size, row count, column count, header hash recorded in the manifest **and re-verified by the experiment runner before training** | integrity | `verify_files()` call in runner | `src/xrlids/datasets/loading.py` | failure injection | mismatch ⇒ abort |
| BS-018 | Provenance route recorded per file: acquisition command/URL/date + classification (official / authorised mirror / third-party mirror / unknown) | scientific provenance | `source_class` field in manifest | `data/manifests/dataset_registry.yaml` | doc review | each dataset has `source_class` and `acquired_via` populated truthfully (CIC-IDS2017 = third-party mirror: **HuggingFace**) |
| BS-019 | PCAP not required for modelling; recorded as optional for parity experiments only | scope control | provenance statement | `docs/phase1/DATASET_PROVENANCE.md` | review | statement present and consistent with manifest |
| BS-020 | No raw dataset file is ever committed; `.gitignore` rules tested | public repo hygiene | `git ls-files data/raw` returns only `.gitkeep` | `.gitignore` | CI check | tracked raw data count == 0 |

## 5. Data-quality requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-021 | Every file audited individually: rows, cols, dtypes, NaN/Inf, duplicates, constant columns, malformed rows, label distribution | no representative-file shortcuts | `results/audits/<dataset>_audit.json` covering **20/20 files** | `scripts/phase1/03_run_audit.py` | audit run | `per_file_audits` length == files present |
| BS-022 | Repeated header rows are detected and rejected as unknown labels, counted per file | known CIC artifact (59 rows in CSE) | rejection rows with reason | `labels/contract.py` | unit test | 25+33+1 CSE header rows all rejected and reported |
| BS-023 | Row accounting chain is complete and reconciles exactly: raw → exact-dup removed → unknown-label rejected → invalid-duration removed → non-finite feature rows dropped → feature-dedup → final population | "no silent row loss" | accounting block per experiment | `preprocessing/cleaning.py`, `splitter.py` | unit test + report lint | `raw − removed == final` and every stage reported in the experiment record |
| BS-024 | Duplicate analysis reports label conflicts: identical feature vectors with different labels are counted and handled by an explicit documented rule | Policy A `keep='first'` silently relabels | `duplicate_label_conflict_count` artifact | `splitting/splitter.py` | unit test with a conflicting fixture | conflict count reported; policy documented in `DATA_CLEANING_POLICY.md` |
| BS-025 | Cleaning rules remain deterministic, ordered and documented (problem, detection, count, action, reason, risk, alternative) | reproducibility | cleaning-steps block | `cleaning.py` | unit test | accounting raises on mismatch (already true — keep it) |
| BS-026 | Known dataset quirks documented: 1,048,575-row cap on 7 CSE files, 84-col Tuesday schema containing `Src IP/Dst IP`, CIC leading-space headers, UNSW train/test note swap | a professor will ask | quirks table in dataset cards | `docs/phase1/DATASET_*.md` | doc review | all four quirks listed with evidence |

## 6. Feature requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-027 | One canonical feature definition per feature: name, equation, units, inputs, edge-case rule, live availability, leakage note | single source of truth | `definitions.py` + generated table | `src/xrlids/features/definitions.py` | unit test per feature | 20/20 features have equation + edge policy + test |
| BS-028 | Raw→semantic column maps must match the headers the pipeline actually sees (**post-cleaning**), one convention for all datasets | **CRITICAL: CIC map keys keep leading spaces while cleaning strips them; CIC-IDS2017 cannot run** | failing test converted to passing | `configs/features/features.yaml` + `cleaning.py` | `tests/data/test_schema_validation.py`, `tests/integration/test_smoke_pipeline.py` | `xrlids.cli smoke` succeeds and all 17 currently failing tests pass |
| BS-029 | R10/R15/R20 frozen by D-002 with per-feature gate answers (Q1–Q10) resolved from evidence, not `unverified` | feature choices must be defensible | decision record + sweep results | `configs/features/features.yaml`, `DECISION_LOG.md` | decision + `results/feature_sweeps/` | `contract_status: frozen` with a decision date, and no gate answer left `unverified` for features in the frozen rung |
| BS-030 | Cross-dataset feature availability matrix computed from real files for all 3 datasets | UNSW supports 4/10 of R10 | generated matrix | `reports/generated/feature_compatibility.md` | regenerate after audit | matrix derived from audited columns for 20/20 files |
| BS-031 | Identifier columns (`Flow ID`, `Src IP`, `Dst IP`, ports, timestamps) are provably excluded from every model input | the 84-col CSE file contains raw IPs | exclusion test | `features/registry.py::is_excluded_column` | unit test loading the Tuesday header | no identifier reaches any feature matrix |

## 7. Training methodology

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-032 | Split = TRAIN (fit scaler/imputer/model) / VALIDATION (α, Platt, threshold, hyperparameters) / TEST (final, once) at 60/20/20 with recorded seed | scientific validity | split manifest | `splitting/splitter.py` | unit tests | manifest records ratios, seed, stratification, hashes |
| BS-033 | Split strategy must be justified per dataset: stratified-random **plus** at least one of temporal or group split where the data supports it; where it cannot, that is documented as a limitation | random split on time-ordered attack days is the weakest option | `SPLIT_METHODOLOGY.md` per dataset + an executed L-05 or an explicit "cannot be performed" with reason | `configs/splits/splits.yaml` | doc + leakage report | for each dataset: either a temporal/group split result, or a written impossibility argument accepted in the audit |
| BS-034 | Leakage checks L-01…L-06 all *executed or explicitly justified*: L-04/L-05 need the IP/timestamp columns to be carried into the splitter (they are currently stripped) | 3 of 6 currently never run | leakage report with `performed: true` or a justification string | `splitting/leakage.py` | unit tests | no check silently `not performed` without reason |
| BS-035 | Duplicate-policy decision (A vs B) recorded with evidence; if A (dedup) is kept, its class-balance effect is measured | A-006 is unvalidated | per-class duplicate accounting before/after | `splitter.py` | report | policy documented + effect quantified in `DATA_CLEANING_POLICY.md` |
| BS-036 | LSTM sequence construction documented *in the config that trains it*: ordering key (file order vs timestamp), gaps, label rule, stride, boundary handling; and verified against the timestamp column if one exists | `lstm_baseline.yaml` still says `ordering_key: null` | sequence-construction block in every LSTM experiment record | `models/lstm.py`, config | unit test asserting recorded ordering key | no LSTM run without a recorded ordering key |
| BS-037 | All stochastic steps seeded (Python/NumPy/torch/sklearn) and recorded | reproducibility | `random_seed` in every record | `utils/seeding.py` | test | record contains seed for split, RF, LSTM, SHAP sampling |

## 8. Evaluation methodology

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-038 | Report accuracy, precision, recall, specificity, FPR, FNR, F1, macro-F1, weighted-F1, balanced accuracy, ROC-AUC, PR-AUC, confusion matrix — all with population size and threshold | imbalance makes accuracy alone misleading | `test_metrics.json` | `evaluation/metrics.py` | metric unit tests | all present for every model in every experiment |
| BS-039 | RF vs LSTM vs fusion comparisons are computed on the **identical aligned population** wherever a comparative claim is made | headline numbers currently use 43,340 vs 43,336 | aligned-population comparison block | `models/fusion.py::compare_components` | report lint | every comparative statement cites one population size |
| BS-040 | Every claim of "significantly"/"outperforms" is backed by either a paired test (e.g. McNemar on disagreements) or is reworded as a point estimate | CLAIM-002 says "significantly" with no test | test statistic + p-value or reworded claim | `CLAIMS_REGISTRY.md` | claim review | no comparative claim without a test or hedge |
| BS-041 | Repeated seeds (≥3) for the primary baseline, reporting mean ± sd for headline metrics | one seed = one draw | multi-seed results | `results/baselines/` | experiment | mean/sd published for RF and LSTM primary runs |
| BS-042 | Confidence intervals (bootstrap, ≥1000 resamples) for headline metrics on the test set | uncertainty | CI fields in metrics | `evaluation/metrics.py` | unit test | every headline metric carries `[lo, hi]` |
| BS-043 | Baseline ladder: majority-class, stratified-random, logistic regression, decision tree, random forest, gradient boosting, LSTM, fusion | RF+LSTM alone cannot justify "our model is good" | `results/baselines/` entries | `src/xrlids/models/` + runner | experiment matrix | all 8 baselines executed on ≥1 dataset with identical protocol |

## 9. Model requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-044 | RF: one documented hyperparameter set (resolve the 100-vs-200 `n_estimators` conflict), class weighting stated, `random_state`, `n_jobs` policy, training time, model size, feature importances | hardware fit (12 cores/14 GB) | model card | `models/random_forest.py` + config | report | single source of truth; model card filled |
| BS-045 | RF/LSTM/preprocessor artifacts are either committed via a model registry with hashes, or reproducible by a one-command retrain documented in the runbook | experiment records currently point at gitignored files | `models/registry/` entries + retrain command | `models/registry/`, `.gitignore` | clone-and-verify | a fresh clone can regenerate or fetch every artifact referenced by a committed record |
| BS-046 | LSTM: documented sequence length/label rule/ordering, batching, hidden size, layers, dropout, optimizer, LR, loss (with class weighting), early stopping, checkpoint file, CPU/GPU behaviour, memory ceiling | §15 of the audit | model card | `models/lstm.py` | model card + memory log | card complete; peak RSS recorded for training |
| BS-047 | LSTM training must not materialise the whole dataset as dense sequence tensors: chunked/streaming sequence construction with bounded memory and deterministic batching | 4 GB CSE file cannot fit | memory profile at dataset scale | `models/lstm.py` | perf test on ≥5 M-row input | peak RSS stays below a documented budget (target <6 GB) |
| BS-048 | Fusion: α tuned on validation only (already true), calibration-aware option tested, disagreement/rescue/degradation analysis retained (already true) | RQ3 | fusion report | `models/fusion.py` | experiment | comparative claim on aligned population (BS-039) |
| BS-049 | Calibration: Brier, ECE, reliability curve for RF/LSTM/fusion on validation and test, with figures committed | FR-018 | calibration figure + JSON | `evaluation/calibration.py` | report | both a machine and a human artifact exist per experiment |
| BS-050 | Threshold: single operational objective chosen by D-003, fitted on validation, frozen with a decision record; 0.5 remains only a labelled neutral reference | current candidates show FPR 0.71 at recall 0.95 — the objective matters | decision entry + frozen threshold | `DECISION_LOG.md`, `evaluation/thresholding.py` | decision + test | `D-003` closed with an objective, threshold recorded in every subsequent experiment |

## 10. Explainability requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-051 | TreeSHAP for RF with documented background size/selection, explain size, seed and aggregation — current 100/200 documented | reproducible attribution | `shap_summary.json` fields | `explainability/shap_analysis.py` | report | methodology block complete |
| BS-052 | Attribution stability: repeat over ≥3 seeds or bootstrapped samples; report rank correlation | single-shot rankings are fragile | stability table | `shap_analysis.py` | experiment | top-5 feature rank stability reported |
| BS-053 | Local explanations available for arbitrary single flows (top positive/negative contributions) — needed by the API/dashboard | demo requirement | local explanation JSON | `shap_analysis.py` | unit test | one flow ⇒ one explanation payload |
| BS-054 | Documentation states SHAP is **model attribution, not causality**, in every surface that shows SHAP output | claims hygiene | caveat string | report generator, API response | lint | caveat present in all SHAP outputs |
| BS-055 | If the fused detector is presented as the decision source, fused/LSTM explainability is either provided or its absence is documented as a limitation | scope honesty | limitation entry | `LIMITATIONS.md` | review | decision recorded either way |

## 11. Domain-generalization requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-056 | All 6 transfer directions executed with a programmatic common-feature contract (already implemented) evaluated **on the target dataset** (currently never done) | RQ5 has zero target results | `results/cross_dataset/` with 6 records | `run_experiment.py --transfer-target` | experiment matrix | 6/6 directions have target metrics |
| BS-057 | D-005 (normalisation policy) decided and recorded before interpreting any transfer result | raw-shift vs per-domain scaling changes the conclusion | decision entry | `DECISION_LOG.md` | decision | D-005 closed |
| BS-058 | Each transfer result reports: common features, missing features, source-only training, target-only testing, taxonomy mapping, expected vs observed shift, interpretation limits | defensibility | transfer report sections | report generator | report lint | all seven fields present |
| BS-059 | Unseen-attack-family / OOD experiment: train without one family, test on it (feasible: 3 datasets, 20+ families) | "what about traffic you never saw?" | `results/ood/` | runner | experiment | ≥1 OOD experiment per dataset |
| BS-060 | Cross-dataset claims are scoped to the direction and contract actually tested | overclaim prevention | claim wording review | `CLAIMS_REGISTRY.md` | review | no claim generalizes across datasets without 6-direction evidence |

## 12. RL response-policy requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-061 | DQN implementation with explicit state (calibrated RF/LSTM/fusion scores ± short history), actions {ALLOW, ALERT, BLOCK}, target network, replay buffer, seeds | RQ7 evidence | code + training curves | `src/xrlids/rl/` (planned) | unit + training run | policy trains reproducibly from a config |
| BS-062 | Environment is a **simulator/replay environment built from recorded detector traces**, never the live network | safety + ethics | environment description + transition source | `src/xrlids/rl/env.py` | review | documented transition provenance; no live packets in training |
| BS-063 | Reward function defined with explicit costs (missed attack, false block, alert, repeated attack, recovery) and a **sensitivity study A/B/C** (config already mandates it) | reward is a hypothesis | sensitivity results | `configs/models/dqn_baseline.yaml` + runner | experiment | 3 reward variants compared on ≥4 metrics |
| BS-064 | Policy evaluated against all five baselines: Always-ALLOW, Always-BLOCK, fixed threshold, RF-only policy, fusion policy | RL must earn its place | comparison table | `results/dqn/` | experiment | table exists; negative result accepted if honest |
| BS-065 | Policy value reported beyond reward: attack caught %, false-block rate, actions per hour, time-to-react | reward alone is opaque | metric block | `results/dqn/` | report | all four reported |
| BS-066 | Offline transition generation from recorded traces + replay evaluation before any enforcement | §24 of the audit | offline-eval artifact | `src/xrlids/rl/` | experiment | offline eval completes with no network side effects |

## 13. Live inference requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-067 | Scapy capture with documented interface, BPF filter, permissions, buffer and drop counters | §25 | capture module + config | `src/xrlids/inference/capture.py` (planned) | system test | packets/s and drop count reported |
| BS-068 | 5-tuple bidirectional flow assembler with FIN/RST termination, idle timeout, active timeout (D-006 decided first) | flow definition must match training | assembler + decision | `src/xrlids/inference/flows.py` | unit tests incl. out-of-order, UDP, malformed, partial flows | D-006 closed; timeout tests pass |
| BS-069 | **Single source of feature maths**: live extraction imports the same `definitions.py` formulas — no duplicated equations | FR-022 | shared-module import test | `src/xrlids/features/` | lint test forbidding re-implementation | grep shows one formula definition per feature |
| BS-070 | Parity experiment: same controlled traffic → dataset-side flow vs Scapy-side flow → per-feature absolute/relative difference vs documented tolerance | without parity live results are invalid | `results/realtime/feature_parity.csv` | `scripts/` parity harness | experiment | every feature PASS with a written tolerance rationale; **one FAIL blocks enforcement** |
| BS-071 | Live inference reports latency (P50/P95/P99) per stage: capture, features, RF, LSTM, fusion, SHAP, policy | NFR-008 | latency report | telemetry module | benchmark | per-stage percentiles published |
| BS-072 | Live output is labelled `prediction`, never `accuracy` (no ground truth) | A-009 | wording lint | dashboard/API | lint | no "live accuracy" string anywhere |

## 14. Safety requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-073 | Safety gate implemented in code: min calibrated confidence, repeat confirmation, cooldown, duplicate suppression, action TTL, rate limit | config alone protects nothing | gate module | `src/xrlids/safety/gate.py` (planned) | unit tests per rule | each rule has a test that fails without it |
| BS-074 | Protected sources loaded from a **local untracked override** (IPs/subnets/interfaces/ports) with non-empty validation before ENFORCE | empty list today ⇒ nothing is protected | startup check | `configs/safety/protected_sources.yaml` + local override | failure injection | ENFORCE refuses to start with an empty protected list |
| BS-075 | Modes OBSERVE → DRY_RUN → ENFORCE with explicit transition command, default OBSERVE, ENFORCE preconditions (parity, replay, dry-run, safety tests, rollback) enforced in code | NFR-011 | mode state machine | safety module | system tests | ENFORCE without preconditions is refused |
| BS-076 | Rollback: every applied action is reversible and its reversal is tested | NFR-006 | rollback log + test | safety module | system test | apply → rollback → verified state |
| BS-077 | Fail-safe: missing model / API / DB / NaN features ⇒ observe-only, never block | architecture constraint | failure-injection tests F-001…F-012 | safety module | `tests/system/` | all 12 injections behave as specified |
| BS-078 | Emergency disable (single command/file) that immediately drops to OBSERVE | demo safety | runbook + test | CLI | test | disable takes effect within one event cycle |

## 15. API / backend requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-079 | `POST /predict` with `{flow_id, features, feature_schema_hash}` → scores + prediction + action recommendation + model id + schema-match flag; schema mismatch is an **error, not a fallback** | inference contract | OpenAPI/JSON schema | `services/ml-api/` | API tests | contract test suite green |
| BS-080 | `POST /explain`, `GET /health`, `GET /model`, `GET /version`, `GET /events?limit=`, `GET /status` | demo + audit | endpoint list | `services/ml-api/` | API tests | all endpoints implemented with documented schemas |
| BS-081 | Validation of request payloads with explicit error codes; documented latency budget per endpoint | robustness | error-response table | `services/ml-api/` | negative tests | malformed input ⇒ 4xx with reason, never a 500 |
| BS-082 | Dashboard never touches ML internals — it only consumes API responses | separation of concerns | dependency rule test | `services/frontend/` | review/test | frontend imports only API client |
| BS-083 | Local-prototype security assumption documented (bind to loopback, no auth in demo, why that is acceptable here) | honest security posture | README section | `docs/operations/` | review | statement present |

## 16. Dashboard requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-084 | Live traffic panel: flows/s, packets/s, active sessions, protocol mix, capture health | §30 | live values from API | `services/frontend/` | demo | values update and trace to capture counters |
| BS-085 | Detection panel: RF score, LSTM score, fusion score, calibrated risk, threshold, predicted class for the selected flow | evidence-first demo | per-flow payload | frontend | demo | each number links to its source event id |
| BS-086 | Explanation panel: top SHAP features with values + interpretation caveat | §30 | explanation payload | frontend | demo | caveat visible |
| BS-087 | Response panel: recommended action, policy confidence/state, safety-gate decision, actual action, reason, cooldown, rollback status | safety visibility | event fields | frontend | demo | gate reason shown for every blocked recommendation |
| BS-088 | History panel: recent incidents, model versions, timestamps, audit trail | auditability | event log query | frontend | demo | any displayed metric traceable to an event id and model version |
| BS-089 | Health panel: CPU, memory, inference latency, capture health, service status | operational honesty | telemetry | frontend | demo | values sourced from measurements, not placeholders |

## 17. Logging requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-090 | Persistent event store per prediction/action: timestamp, flow id, 5-tuple, features (or hash), rf/lstm/fusion/calibrated scores, predicted class, explanation ref, recommended action, executed action, gate decision + rejection reason, rollback, latency, model version, schema hash | §29 | event schema + rows | `services/backend/` (planned) | integration test | a demo run yields a queryable trail covering all fields |
| BS-091 | Audit log is append-only and survives restart | trust | log file/DB with restart test | backend | system test | trail intact after restart |
| BS-092 | Every experiment writes a complete experiment card (ID, RQ, hypothesis, dataset+hashes, feature contract+hash, preprocessing, split, leakage, model config, seed, env, hardware, duration, validation method, test population, metrics, artifacts, conclusions, limitations) | §18 | experiment cards from template | `docs/experiments/` | report lint | no metric exists without a card |

## 18. Deployment requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-093 | One documented clean-setup path (venv, pinned deps, package install) that works from a fresh clone | §31 | runbook | `REPRODUCIBILITY.md`, `docs/operations/DEPLOYMENT_RUNBOOK.md` | fresh-clone rehearsal | following the runbook reaches a healthy `/health` |
| BS-094 | Service topology documented: processes, ports, env vars, start/stop commands, health checks | ops | runbook tables | `deployment/` | rehearsal | all services start/stop per documented commands |
| BS-095 | Model loading with schema-hash and checksum verification at startup; failure ⇒ OBSERVE | safety | startup log | inference/API | failure injection | corrupt model ⇒ refuses to serve predictions |
| BS-096 | CPU-only first-class; GPU optional and optional-only | actual hardware | env fingerprint | runtime | review | no step requires CUDA |

## 19. Resource constraints

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-097 | Chunked CSV ingestion with `usecols`+`chunksize`, memory-efficient dtypes, bounded materialisation; whole-file `read_csv` forbidden for files > documented threshold | 4.05 GB file OOMs on 14 GB | memory profile | `datasets/loading.py` | perf test | peak RSS recorded and < budget for every dataset file |
| BS-098 | Documented RAM/CPU/disk/runtime budget per stage (load, clean, features, RF, LSTM, SHAP, inference, all-services) | §32 | budget table in runbook | docs | measurement | table filled from measurements, not estimates |
| BS-099 | Sampling, where scientifically necessary, is stratified, seeded, size-documented, and its methodological consequence stated | "don't shrink the research silently" | sampling block in experiment record | runner | report lint | every sampled run is labelled `PRELIMINARY_SUBSAMPLE` (already true) and states the inference limit |
| BS-100 | Training is resumable (checkpoint per epoch) and runs are idempotent given config+seed | long runs on modest hardware | checkpoint files | `models/lstm.py` | test | kill → resume → identical final metrics |

## 20. Testing requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-101 | **Zero failing tests** — the suite must be green; docs must state the true count | 17/100 fail today; docs claim 101 passing | `pytest` exit 0 | `tests/` | CI | `pytest -q` passes; `PROJECT_STATUS.md`/`REPRODUCIBILITY.md` counts match reality |
| BS-102 | Unit coverage: label contract (incl. normalization edge cases), feature formulas (incl. zero-duration, ratio flooring), splits, leakage, preprocessing, metrics, calibration, thresholding, error analysis, SHAP | math must be tested | test list | `tests/unit/` | coverage report | every module in §0 table has ≥1 failing-without-it test |
| BS-103 | Integration: dataset→features→split→models on fixtures **and** on a real-file sample for each dataset | CIC path is broken yet "tested" green nowhere | per-dataset integration test | `tests/integration/` | CI | one real-sample test per dataset |
| BS-104 | ML pipeline: reproducibility (same seed ⇒ same metrics), artifact generation, registry round-trip | reproducibility | test | `tests/model/`, `tests/integration/` | CI | bit-stable metrics on CPU |
| BS-105 | System: API contract, event persistence, dashboard data flow, capture pipeline | §33 | tests | `tests/system/`, `tests/api/` | CI | directories are non-empty and green |
| BS-106 | Safety: protected host, cooldown, TTL, dry-run, rollback, empty-protected-list refusal | safety | tests | `tests/system/` | CI | one test per gate rule |
| BS-107 | Failure injection F-001…F-012 executed and recorded | §33 / `docs/failures/` | injection results | `tests/system/` | run | 12/12 documented with observed behaviour |
| BS-108 | Performance tests: throughput, latency percentiles, memory ceiling, startup time | NFR-009 | perf report | `results/realtime/` | benchmark | numbers published with hardware context |

## 21. Reproducibility requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-109 | Every artifact carries: experiment id, git commit, dataset SHA-256(s), feature-schema hash, seed, timestamp, environment, artifact version (implemented — keep) | provenance | sidecars | `artifacts/metadata.py` | test | sidecar present for every artifact |
| BS-110 | Generated reports are **generated**: no hand-edited content, no hard-coded statuses, commit hash written by the generator only | two commits hand-edited report hashes; generator hard-codes `DATA_NOT_AVAILABLE` | `git diff` empty after regeneration | `generate_reports.py` | CI check | report regeneration is diff-clean; statuses read from the manifest |
| BS-111 | Dependencies pinned with hashes (lockfile) and env fingerprint compared on demand | environment drift | lockfile | repo root | install test | fresh env matches recorded fingerprint |
| BS-112 | A single documented command regenerates each published number from committed inputs | §21 | command table | `REPRODUCIBILITY.md` | rehearsal | each claim's number reproduced exactly (already true for metrics from predictions) |
| BS-113 | Dataset acquisition is reproducible: documented source per file, verification command, and integrity re-check | provenance | runbook section | `REPRODUCIBILITY.md` | review | re-verification passes on a clean checkout with data restored |

## 22. Documentation requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-114 | Status documents are true: `PROJECT_STATUS.md`, `README.md`, `REPRODUCIBILITY.md`, `DATASET_PROVENANCE.md`, `EXPERIMENT_REGISTRY.md`, `FUNCTIONAL_REQUIREMENTS.md` must all match the manifest and results | 6 documents currently contradict reality | doc-vs-evidence audit | `docs/`, root | review | each status line maps to an artifact that exists |
| BS-115 | Dataset card per dataset (source, route, licence, files, hashes, row counts, labels, quirks, limitations) | professor question #1 | cards | `docs/phase1/DATASET_CATALOG.md` (missing) | review | 3 cards complete |
| BS-116 | Data dictionary (every column used or excluded, with meaning and unit) | feature defence | dictionary | `docs/phase1/DATASET_SCHEMAS.md` (missing) | review | all columns of 3 schemas documented |
| BS-117 | Label specification with per-dataset dictionary of every raw label → canonical → family, and the observed count for each | label defence | label dictionary generated from audits | `docs/phase1/LABEL_CONTRACT.md` | generator | tables generated from `results/audits/*`, not typed |
| BS-118 | Methodology document: datasets, cleaning, splits, models, tuning, calibration, threshold, evaluation — one narrative | viva backbone | doc | `docs/phase1/METHODOLOGY.md` (missing) | review | complete |
| BS-119 | Model cards for RF, LSTM, fusion, DQN (intended use, data, hyperparameters, metrics, limits, calibration, latency) | §34 | cards | `docs/phase2/model_cards/` (empty) | review | 4 cards |
| BS-120 | Experiment cards for every recorded experiment (template exists; 0 filled) | traceability | cards | `docs/experiments/` | lint | ≥1 card per experiment dir in `results/experiments/` |
| BS-121 | Failure reports for every real failure encountered (17 failing tests, CIC pipeline break, memory events) | failures are evidence | reports | `docs/failures/` (empty) | review | ≥3 reports including the CIC column-map bug |
| BS-122 | Threat/risk model: what the system can and cannot defend, trust boundaries, abuse cases | safety defence | doc | `docs/` (missing) | review | exists |
| BS-123 | Runbooks: live deployment runbook, safety runbook, rollback, incident replay, observability | demo safety | runbooks | `docs/operations/` (all ⬜) | rehearsal | 4 runbooks rehearsed once |
| BS-124 | Limitations document: explicit list of claims that may **not** be made with current evidence | overclaim prevention | `LIMITATIONS.md` (missing) | `docs/` | review | present and consistent with claims registry |
| BS-125 | Viva pack: 10 documents, each answer = short answer, technical answer, evidence, experiment | §37 | viva docs (10 missing) | `docs/viva/` | review | 10/10 filled with evidence pointers |

## 23. Professor-demo requirements

| ID | Requirement | Rationale | Evidence needed | Implementation location | Validation | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- |
| BS-126 | One command sequence: start system → dashboard online → generate/replay controlled traffic → flows → features → RF+LSTM → fusion → calibration → explanation → policy → safety gate → ALLOW/ALERT/BLOCK → logged → dashboard evidence → rollback | §38 | demo script + recording | `docs/operations/DEPLOYMENT_RUNBOOK.md` | full rehearsal | demo runs end-to-end without manual fixes |
| BS-127 | Every demo stage labelled **real / replayed / simulated / synthetic** in the UI itself | "never pretend simulated results are live" | stage labels | frontend | demo | labels visible |
| BS-128 | Demo uses controlled traffic only (lab VMs / replay), never production traffic or the operator's own management path | safety | demo topology diagram | runbook | review | topology documented; protected hosts excluded |
| BS-129 | A "trace this number" walkthrough: pick any dashboard number → event id → model version → config → dataset hash → commit, in ≤4 steps | evidence-first | walkthrough doc | docs | rehearsal | walkthrough succeeds for 3 randomly chosen numbers |
| BS-130 | Failure demo: inject one failure (model missing / API down) and show the system degrading to OBSERVE | failure handling | demo script section | runbook | rehearsal | demonstrated |

## 24. Limitations

The finished repository must state, in one place, that the following are **not** claimed unless the
corresponding gap is closed:

| ID | Limitation statement | Closed by |
| --- | --- | --- |
| BS-131 | No accuracy/generalization claim beyond the exact dataset/day/contract tested | GAP-M01..M03 |
| BS-132 | No "real-time intrusion detection" claim until parity (BS-070) passes | GAP-L01 |
| BS-133 | No "RL improves response" claim until BS-064 baselines are run | GAP-R01 |
| BS-134 | No "autonomous response is safe" claim until BS-073…BS-078 are implemented and tested | GAP-S01 |
| BS-135 | No causal interpretation of SHAP | docs |
| BS-136 | No live "accuracy" claim (no ground truth) | BS-072 |
| BS-137 | Single-seed, single-day, single-attack-family results are explicitly labelled preliminary | BS-041, BS-013 |
| BS-138 | The detector's current operating characteristics (weak recall at low FPR) are disclosed wherever metrics are shown | BS-038 |

## 25. Acceptance criteria — definition of "finished"

The prototype is **finished** when all of the following are simultaneously true:

1. `pytest -q` exits 0 and the documented test count matches the actual count (BS-101).
2. All three datasets audited file-by-file (20/20), manifest truthful including provenance class and
   the corrected UNSW reference counts (BS-014…BS-026).
3. The CIC-IDS2017 pipeline runs end-to-end (BS-028) and each dataset has a full in-domain
   baseline on the frozen feature contract (BS-029, BS-032).
4. Baseline ladder complete (BS-043); primary results carry CIs and ≥3 seeds (BS-041, BS-042);
   comparative claims are statistically backed or reworded (BS-040).
5. D-002, D-003, D-005, D-006 closed with recorded evidence; duplicate-policy decision recorded
   (BS-029, BS-050, BS-057, BS-068, BS-035).
6. All 6 transfer directions and ≥1 OOD experiment executed and honestly interpreted (BS-056…BS-060).
7. DQN trained offline on replayed traces, compared against all 5 baselines, reward sensitivity A/B/C
   reported (BS-061…BS-066).
8. Live path exists with per-feature parity PASS and per-stage latency measurements (BS-067…BS-072).
9. Safety gate implemented, protected-list enforced, 12 failure injections pass, rollback demonstrated
   (BS-073…BS-078, BS-107).
10. API + event store + dashboard exist and the "trace this number" walkthrough succeeds (BS-079…BS-092,
    BS-129).
11. Memory budgets met on the actual machine: every dataset file processes without OOM (BS-097, BS-098).
12. Report regeneration is diff-clean; no hand-edited hashes; status docs match the manifest (BS-110, BS-114).
13. Documentation set complete: dataset cards, dictionary, label spec, methodology, model cards,
    experiment cards, failure reports, threat model, runbooks, limitations, viva pack (BS-114…BS-125).
14. Full professor demo rehearsed end-to-end with stage honesty labels (BS-126…BS-130).

---

## Gap register (authoritative, severity-tagged)

Severity: `CRITICAL` = cannot call the prototype complete without it · `HIGH` = required for a
defensible research claim · `MEDIUM` = required for a polished, traceable system · `LOW` = polish.

| ID | Component | Current state | Desired state | Severity | Why it matters | Dependency | Evidence | Implementation required | Validation required | Documentation required | Acceptance criteria |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GAP-D01 | CIC-IDS2017 pipeline | `extract_semantics` fails: map keys have leading spaces, cleaning strips them | CIC runs end-to-end | **CRITICAL** | primary benchmark unusable; 13 tests fail | BS-028 | reproduced live + failing tests | align column-map convention with cleaning (one convention, applied consistently) | `tests/data/test_schema_validation.py`, `tests/integration/test_smoke_pipeline.py`, `xrlids.cli smoke` green | failure report in `docs/failures/` | smoke command exits 0 on CIC fixture and real sample |
| GAP-D02 | Test suite | 17/100 failing; docs claim 101 passing | green suite, true count | **CRITICAL** | any "tests pass" claim is false | GAP-D01, label-normalization fix | `pytest -q` exit 1 | fix D01 + the empty-string unicode replacement in `label_mapping.yaml` | `pytest -q` exit 0 | correct `PROJECT_STATUS.md`/`REPRODUCIBILITY.md` counts | exit 0 and counts match |
| GAP-D03 | Label normalization | `unicode_replacements` contains an empty-string key ⇒ `normalize("BENIGN") = "-B-E-N-I-G-N-"` | sane normalization | **CRITICAL** | latent correctness hazard; breaks `classify()` contract | BS-002 of label work | runtime proof | remove/repair the empty-key replacement (it is a mojibake artifact) | 3 label tests pass; label counts unchanged | note in `LABEL_CONTRACT.md` | normalization tests pass and audit label counts identical to before |
| GAP-D04 | CSE-2018 audit coverage | 1/10 files audited (9 incl. 4.05 GB 84-col file with raw IPs) | 10/10 audited | **CRITICAL** | schema/label claims cover 10% of data | BS-021 | `results/audits/cse_cic_ids2018_audit.json` n_files=1 | run `03_run_audit.py` after chunked-reading fix (memory) | audit covers 10 files | updated audit reports | `per_file_audits` length 10 |
| GAP-D05 | Dataset provenance route | manifest says "(UNB)" / "AWS mirror"; CIC actually from HuggingFace; CSE/UNSW route undocumented | truthful provenance class per file | **CRITICAL** | provenance is a core research claim | BS-018 | HF cache metadata | record acquisition route + `source_class` per dataset | review | `DATASET_PROVENANCE.md` updated | each dataset has source class + acquired_via |
| GAP-D06 | UNSW manifest reference counts | notes say testing=175,341 / training=82,332 (swapped) | matches official (training 175,341 / testing 82,332) | **HIGH** | documented falsehood in the authoritative manifest | — | official UNSW page + local `wc -l` | correct the notes (documentation fix, not a data change) | re-read manifest | same | notes match files |
| GAP-D07 | Generated-report integrity | generator hard-codes `DATA_NOT_AVAILABLE` (lines 559/560/591); commit hashes hand-edited (`d854a76`, `e91a016`) | fully derived, diff-clean regeneration | **CRITICAL** | violates NFR-007; erodes trust in every report | BS-110 | code inspection + git show | derive statuses from manifest; forbid manual hash edits (CI check) | regenerate ⇒ empty diff | report note | diff-clean regeneration |
| GAP-D08 | Status docs vs reality | README/PROJECT_STATUS/REPRODUCIBILITY/PROVENANCE/EXPERIMENT_REGISTRY/FR table all contradict the manifest | consistent, true statuses | **CRITICAL** | professor reads these first | GAP-D04 | side-by-side comparison in audit §5/§7 | update the six documents | doc-vs-evidence review | same | every status line maps to an artifact |
| GAP-D09 | Requirements table | all FR-001…FR-032 marked ⬜ though most are implemented | accurate verification status | **MEDIUM** | understates and confuses progress | — | audit §5 | mark each FR with its real evidence pointer | review | same | no FR marked ⬜ without cause |
| GAP-D10 | Model artifacts | `.joblib`/`.pt` gitignored; records reference missing files | registry with hashes or one-command retrain | **HIGH** | clone cannot reproduce records | BS-045 | `git ls-files` output | model registry entries + retrain command | clone rehearsal | runbook section | fresh clone can regenerate or fetch artifacts |
| GAP-D11 | Experiment registry | Markdown says "None yet" | lists 3 experiments with statuses | **MEDIUM** | index is wrong | — | file content | update registry (incl. subsample flags) | review | same | registry matches `results/experiments/` |
| GAP-D12 | Stale generated artifacts | `dataset_summary.json` has 1 dataset; `label_rejections.csv` misses 34 rows; `results_summary.md` shows only smoke; `transfer_report.md` uses obsolete feature names | regenerated from current data | **HIGH** | committed evidence is stale | BS-021, GAP-D04 | inspection | re-run audit + report generation | regenerate | reports | artifacts match current audits |
| GAP-M01 | In-domain baselines | only 1 dataset, 1 day, 1 attack family (infiltration), 1 contract | 3 datasets × frozen contract | **CRITICAL** | RQ1 evidence is a single hard day | BS-029, GAP-D01 | experiment records | run baselines on CIC (8 files) + CSE (10 files) + UNSW (4-feature) | full metrics with CIs | experiment cards | ≥3 dataset baselines executed |
| GAP-M02 | Baseline ladder | RF/LSTM/fusion only | + majority, random, LR, DT, GBM | **HIGH** | cannot claim sophistication is useful | BS-043 | `results/baselines/` empty | implement + run 5 extra baselines | same protocol | model cards | 8 baselines present |
| GAP-M03 | Multi-seed / uncertainty | single seed 42, no CIs | ≥3 seeds + bootstrap CIs | **HIGH** | single-draw results are not defensible | BS-041, BS-042 | records show one seed | multi-seed runner + CI computation | compare variance | metrics docs | mean±sd and CIs published |
| GAP-M04 | Multiclass / per-family analysis | binary only | per-family error reporting | **HIGH** | "which attacks fail?" unanswerable | BS-012 | `error_analysis.json` | add family-wise metrics | unit test | `ERROR_ANALYSIS.md` | per-family table per experiment |
| GAP-M05 | Threshold objective | D-003 open; candidates show FPR 0.71 @ recall 0.95 | decided, frozen, justified | **HIGH** | operational point undefined | BS-050 | `threshold_candidates.json` | decision + freeze | decision record | updated reports | D-003 closed |
| GAP-M06 | Feature contract freeze | D-002 open; every gate Q7/Q8 `unverified` | frozen rung with evidence | **HIGH** | feature choice undefended | BS-029 | `features.yaml` | feature sweep (R10/R15/R20 × datasets × models) | sweep results | decision record | `contract_status: frozen` |
| GAP-M07 | LSTM temporal validity | ordering key undefined in config; file-order windows assumed temporal; random split | verified ordering + documented construction | **HIGH** | RQ2's premise unproven | BS-036, BS-033 | `lstm_baseline.yaml` nulls | record ordering key; verify against timestamps; consider temporal split | test + leakage L-05 | `LSTM_METHODOLOGY.md` | ordering verified or limitation stated |
| GAP-M08 | LSTM memory/scale | full dense sequence tensors in RAM | chunked/streaming sequences, bounded memory, checkpointing | **HIGH** | cannot train on full CSE data | BS-047, BS-100 | code inspection | sequence generator with budget + resume | perf test | methodology doc | peak RSS within budget on ≥5 M rows |
| GAP-M09 | Class imbalance in LSTM | plain BCE, no weighting | documented imbalance handling | **MEDIUM** | recall collapse partially explained by this | BS-046 | `lstm.py` | `pos_weight`/focal option + ablation | compare | model card | decision documented with evidence |
| GAP-M10 | Fusion narrative | "outperforms" claimed; at 0.5 fusion recall 0.175 vs RF 0.474 | metric-qualified, aligned-population comparison | **HIGH** | claim is misleading as written | BS-039, BS-040 | audit §7 | reword claims + aligned comparison + significance | tests | claims registry update | wording matches evidence |
| GAP-M11 | CLAIM-002 wording | "significantly reducing false alarms" without a test and without recall context | hedged or tested | **HIGH** | overclaim in the registry | BS-040 | registry + metrics | add recall/FNR context or statistical test | — | registry | claim states both sides |
| GAP-M12 | SHAP stability | 100 bg / 200 explain, 1 seed, RF only | stability + scope statement | **MEDIUM** | rankings may be sampling noise | BS-052 | `shap_summary.json` | stability runs | rank-correlation report | `SHAP_METHODOLOGY.md` | stability reported |
| GAP-M13 | Calibration artifacts | JSON only, no figures; no operational calibration story | figures + chosen operating calibration | **MEDIUM** | hard to defend in viva | BS-049 | artifacts | plot generation | report | calibration note | figures committed |
| GAP-X01 | Cross-dataset target evaluation | 0/6 directions executed (UNSW now present) | 6/6 | **CRITICAL** | RQ5 has no results | BS-056, GAP-D04 | `results/cross_dataset/` empty | run 6 transfers with common contract | metrics per direction | `transfer_report.md` | 6/6 records |
| GAP-X02 | Normalisation policy | D-005 open | decided | **HIGH** | transfer interpretation depends on it | BS-057 | decision log | decision | — | decision record | D-005 closed |
| GAP-X03 | OOD / unseen family | none | ≥1 per dataset | **HIGH** | "unseen traffic" question unanswerable | BS-059 | `results/ood/` empty | leave-one-family-out runner | metrics | report | ≥3 OOD runs |
| GAP-R01 | DQN | config only | trained policy + 5 baselines + sensitivity | **CRITICAL** | RQ7 zero evidence; title claims RL | BS-061…066 | no `src/xrlids/rl/` | env + agent + offline training + evaluation | tests + experiment | `docs/phase2` model card | baseline comparison table exists |
| GAP-R02 | Reward justification | historical reward marked "hypothesis"; A/B/C undefined | sensitivity study | **HIGH** | reward is value-laden | BS-063 | config TODOs | define B/C, run study | results | decision record | 3 variants compared |
| GAP-R03 | Simulator provenance | none | documented trace-derived environment | **CRITICAL** | "how was DQN trained?" must be answerable | BS-062 | — | replay environment from recorded detector traces | review + tests | methodology doc | transition provenance documented |
| GAP-L01 | Live capture/flows/parity | nothing | capture + assembler + parity PASS | **CRITICAL** | RQ8 zero evidence | BS-067…070, D-006 | `docs/phase3/README.md` ⬜ | implement capture, flow builder, parity harness | parity CSV with tolerances | parity report | every feature within tolerance |
| GAP-L02 | Shared feature maths live vs offline | only offline exists | single-source import verified | **HIGH** | duplicated formulas = silent drift | BS-069 | — | live extractor imports `definitions.py` | lint test | inference contract update | one definition per feature |
| GAP-L03 | D-006 flow policy | open | decided | **HIGH** | blocks parity and live everything | BS-068 | decision log | decision | — | decision record | D-006 closed |
| GAP-S01 | Safety gate code | configs only | implemented + tested | **CRITICAL** | nothing prevents blocking anything | BS-073…078 | empty safety tests | gate module with all rules | unit/system tests | safety runbook | every rule tested |
| GAP-S02 | Protected sources | empty lists | local override, non-empty enforcement | **CRITICAL** | ENFORCE would protect nothing | BS-074 | `protected_sources.yaml` | override mechanism + startup refusal | failure test | safety runbook | ENFORCE refuses empty list |
| GAP-S03 | Failure injection F-001…F-012 | all ⬜ | executed and recorded | **HIGH** | "what if it fails?" unanswerable | BS-107 | `docs/failures/README.md` | 12 injection tests | results | 12 failure reports | 12/12 documented |
| GAP-B01 | ML API | empty dir | `/predict /explain /health /model /version /events` + schemas | **CRITICAL** | demo and dashboard need it | BS-079…081 | `services/ml-api/.gitkeep` | implement service | API tests | API contract doc | contract tests green |
| GAP-B02 | Event store / audit log | none | persistent per-event trail with all fields | **CRITICAL** | "auditable system" claim | BS-090…091 | — | implement store + schema | integration test | schema doc | trail queryable after restart |
| GAP-B03 | Dashboard | empty dir | panels per BS-084…089 | **CRITICAL** | professor-facing evidence surface | BS-084…089 | `services/frontend/.gitkeep` | implement | demo | screenshots/walkthrough | all panels sourced from API |
| GAP-P01 | Multi-file loading | single file only | all files, per-file provenance | **HIGH** | benchmarks must cover full datasets | BS-010 | runner code | chunked multi-file loader | integration test | experiment record shows all files | records list every file+hash |
| GAP-P02 | Checksum enforcement | config keys ignored | runner verifies before training | **HIGH** | integrity claim unenforced | BS-011 | grep shows `verify_files` unused | call `verify_files` in runner | corruption test | runbook | mismatch aborts |
| GAP-P03 | Memory ceiling | whole-file `read_csv`; 4.05 GB file OOMs | chunked ingestion | **CRITICAL** | largest file unusable on 14 GB | BS-097 | audit §15 | chunked reader + dtypes | RSS measurement | resource table | every file processes within budget |
| GAP-P04 | Duplicate label-conflict analysis | `keep='first'` silently | conflicts counted + policy documented | **HIGH** | possible silent relabelling | BS-024 | `splitter.py` | conflict counter | unit test | cleaning policy | conflict count reported |
| GAP-P05 | Leakage check coverage | L-03/04/05 never run, L-06 asserted | executed or justified | **HIGH** | "no leakage" claim incomplete | BS-034 | leakage reports | carry IP/timestamp into splitter where available | tests + report | `LEAKAGE_AUDIT.md` | no silent `not performed` |
| GAP-P06 | Split strategy | random only | temporal/group where possible | **HIGH** | random split on attack-day data is weakest option | BS-033 | `SplitConfig` | implement temporal/group path + run | leakage report | `SPLIT_METHODOLOGY.md` | per-dataset justification |
| GAP-T01 | System/API/performance tests | dirs empty | implemented | **MEDIUM** | "pytest passes" is not a test strategy | BS-105…108 | `tests/system/` empty | write tests | CI | test strategy doc | suites exist and pass |
| GAP-O01 | Operations docs | 4 runbooks ⬜ | written + rehearsed | **HIGH** | demo cannot be run safely without them | BS-093…094, BS-123 | `docs/operations/README.md` | write runbooks | rehearsal notes | runbooks | rehearsed once |
| GAP-O02 | Documentation set | viva 10/11 ⬜, no dataset cards/dictionary/methodology/model cards/limitations/threat model/experiment cards | complete | **HIGH** | viva defence requires them | BS-114…BS-125 | audit §5 | write docs from artifacts | review | all | checklist complete |
| GAP-O03 | Experiment cards | template only, 0 filled | one per experiment | **MEDIUM** | traceability index gap | BS-120 | `docs/experiments/` | fill from records | lint | cards | ≥3 cards |
| GAP-O04 | Failure reports | none recorded though ≥3 real failures occurred | documented failures | **MEDIUM** | failures are evidence | BS-121 | `docs/failures/` empty | write ≥3 reports | review | reports | ≥3 reports |
| GAP-DM01 | End-to-end demo | impossible today | rehearsed full demo with stage honesty labels | **CRITICAL** | final deliverable | all above | — | build + rehearse | demo checklist | demo script | BS-126…130 satisfied |

---

*This specification supersedes any status claim found elsewhere in the repository where they
disagree; the audit document is the evidence base for every gap above.*
