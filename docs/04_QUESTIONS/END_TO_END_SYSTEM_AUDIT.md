# END-TO-END SYSTEM AUDIT — XRL-IDARS

Audit date: 2026-10-02 · Audited commit: `e91a016` (HEAD at audit time; `0ebc39b` at audit start —
a concurrent commit `e91a016` landed during the audit) · Working tree: clean at audit start.

**Method.** Nothing in this repository was accepted because a file exists or a status column says
"verified". Every claim below is backed by a command that was actually run and its output recorded
in §O of the closing report. Where evidence is missing, the entry says *no evidence* rather than
guessing.

**Headline.** The Phase-1 research *framework* is genuinely good — provenance manifests, label
rejection, train-only preprocessing, validation-only tuning, calibration, artifact metadata and an
honest claims registry all exist and are real. The *empirical and documentation state* is not:
17 of 100 tests fail, the CIC-IDS2017 pipeline cannot execute at all, 19 of 20 dataset files have
never been audited by tooling, several "generated" reports contain hard-coded or hand-edited
statements, and everything past offline scoring (RL, live capture, API, dashboard, safety
enforcement) is configuration-only.

---

## 0. Component traceability (pipeline reconstruction)

The real executable path today is **only**:

```text
single CSV file (config "dataset.file")
  → pd.read_csv(low_memory=False)                       [scripts/phase1/run_experiment.py]
  → clean_dataset_frame()  (strip headers, drop exact dup rows, reject unknown labels,
                            drop negative duration, reconcile row accounting)
                            [src/xrlids/preprocessing/cleaning.py]
  → extract_semantics()  raw column → semantic field    [src/xrlids/features/compute.py]
  → compute_features()   semantic → canonical features  [src/xrlids/features/definitions.py]
  → drop rows with any non-finite rung feature
  → build_splits()  stratified random 60/20/20 + optional Policy-A feature dedup
                    + leakage audit L-01…L-06           [src/xrlids/splitting/]
  → Preprocessor.fit(train only)  median impute + StandardScaler
  → RandomForestDetector.fit / predict_proba            [src/xrlids/models/random_forest.py]
  → build_sequences(T=5, within split) → LSTMDetector.fit → predict_proba
  → align_scores → tune_fusion_alpha(on validation) → fuse_scores
  → evaluate() on test @0.5                             [src/xrlids/evaluation/metrics.py]
  → threshold_sweep + candidates (validation only)
  → PlattCalibrator(validation) → calibration_report
  → compute_error_analysis / analyze_model_disagreements
  → compute_rf_shap_explanations (TreeSHAP, 100 bg / 200 explain)
  → write JSON + CSV artifacts + experiment_record.json + experiment_report.md
```

Everything to the right of "SHAP" in the project's target pipeline — response policy, safety gate,
action, event store, dashboard, live capture — **does not exist as code**.

| Component | Exists? | Tested? | Executed on real data? | Connected? | Evidence | Problems |
| --- | --- | --- | --- | --- | --- | --- |
| Dataset registry + SHA verify | ✅ | ✅ | ✅ (all 20 files re-hashed in this audit, all match) | ✅ | `data/manifests/dataset_registry.yaml`, `src/xrlids/datasets/loading.py::verify_files` | `verify_files()` is never called by the experiment runner; `require_verified_checksums: true` in configs is **not enforced** |
| Multi-file dataset loading | ❌ | ❌ | ❌ | ❌ | runner uses `existing_files[0]` or one `dataset.file` | no way to run 8-file CIC or 10-file CSE as one population |
| Schema validation | ✅ | ❌ (3 tests fail) | 🟡 20/20 files exist but only 11 audited by tooling | ✅ | `src/xrlids/datasets/schema.py`, `results/audits/*` | validates **raw** headers, while cleaning **strips** headers → the two disagree for CIC-IDS2017 |
| Label contract | ✅ | ❌ (3 tests fail) | ✅ | ✅ | `src/xrlids/labels/contract.py` | `unicode_replacements` contains an **empty-string key**; `normalize("BENIGN") == "-B-E-N-I-G-N-"`. Works only because both sides are normalised; breaks `classify()` on pre-normalised input |
| Cleaning + row accounting | ✅ | ✅ | ✅ | ✅ | `cleaning.py`, accounting raises on mismatch | duplicate rows dropped **before** label rejection; no label-conflict check on duplicates |
| Feature registry + formulas | ✅ | ❌ (3 tests fail) | 🟡 only on CSE | ✅ | `definitions.py`, `features.yaml` | `column_maps_status: unverified_pending_audit` still; R10/R15/R20 not frozen (D-002) |
| **CIC-IDS2017 feature extraction** | ❌ | ❌ | ❌ | ❌ | reproduced live: `FeatureValidationError: missing [' Flow Duration', ' SYN Flag Count', …]` | map keys keep leading spaces; `clean_dataset_frame` strips them → **the primary benchmark cannot run** |
| Splitting + leakage audit | ✅ | ✅ | ✅ | ✅ | `results/experiments/*/leakage_report.json` | L-03/L-04/L-05 always `not performed`; L-02 is an exact-match-at-6dp proxy ≈ L-01; L-06 asserted, never tested |
| Preprocessing (train-only) | ✅ | ✅ | ✅ | ✅ | `preprocessing/pipeline.py` | correct; imputation medians fit on train only |
| Random Forest | ✅ | ✅ | ✅ | ✅ | `test_metrics.json`, `.joblib` (untracked) | weak result (AUC 0.644); `n_estimators` differs between config (100) and default (200) |
| LSTM | ✅ | ✅ | ✅ | ✅ | `lstm.pt` (untracked) | whole dataset materialised as dense `(n,T,F)` tensors in RAM; no class weighting; "temporal" ordering never verified |
| Fusion + α tuning (validation-only) | ✅ | ✅ | ✅ | ✅ | `fusion.py`, experiment records | correct isolation; but headline RF vs fusion numbers are on **different populations** (43,340 vs 43,336) |
| Calibration | ✅ | ✅ | ✅ | ✅ | `calibration_report.json` | raw RF validation ECE 0.215 → calibrated; no reliability figure committed |
| Threshold sweep | ✅ | ✅ | ✅ | ✅ | `threshold_candidates.json` | objective D-003 open (correct); candidates show detector is weak (FPR 0.71 at recall 0.95) |
| SHAP | ✅ | ✅ | ✅ | ✅ | `shap_summary.json` | 100-row background / 200-row explain sample, no stability analysis; RF only |
| Error analysis | ✅ | ✅ | ✅ | ✅ | `error_analysis.json` | good: confusion, confidence distributions, disagreement, fusion rescues |
| Cross-dataset transfer | 🟡 | 🟡 | 🟡 (source-side only, 2,972-row subsample) | 🟡 | `EXP-P1-TRANSFER-CSE-TO-UNSW-001` | target evaluation recorded `DATA_NOT_AVAILABLE` although UNSW files now exist; report uses **obsolete feature names** |
| DQN / RL | ❌ config only | ❌ | ❌ | ❌ | `configs/models/dqn_baseline.yaml` | no `src/xrlids/rl/`, no simulator, no transitions, no baselines |
| Live capture / flow builder / parity | ❌ | ❌ | ❌ | ❌ | `docs/phase3/README.md` all ⬜ | nothing implemented |
| Safety gate code | ❌ config only | ❌ | ❌ | ❌ | `configs/safety/*.yaml` | no enforcement code, no cooldown/rollback implementation |
| ML API / backend / dashboard | ❌ | ❌ | ❌ | ❌ | `services/*/.gitkeep` | empty directories |
| Experiment cards | 🟡 | — | — | ❌ | `docs/experiments/EXPERIMENT_REGISTRY.md` | registry still says "**_None yet._** No datasets have been acquired and no models trained" |
| Viva documents | ❌ | — | — | ❌ | `docs/viva/README.md` | 10 of 11 required documents ⬜ |

---

## 1. What actually exists

1. **A real, hash-verified local copy of all three target datasets (20 CSV files, ~7.8 GB).**
2. A single-package Python library `src/xrlids/` (datasets, labels, features, preprocessing,
   splitting, models, evaluation, explainability, experiments, artifacts, utils) — quality code,
   defensive, documented.
3. Three experiment result directories, of which **one** (`EXP-P1-CSE2018-R10-001`) is a
   full single-file run and two are 2,972-row stratified subsamples explicitly marked
   `PRELIMINARY_SUBSAMPLE`.
4. Committed evidence artifacts per experiment: `experiment_record.json`, `test_metrics.json`,
   `predictions_test.csv`, `split_manifest.json`, `leakage_report.json`, `calibration_report.json`,
   `threshold_candidates.json`, `error_analysis.json`, `shap_summary.json`, `experiment_report.md`.
5. Dataset audit artifacts for 11 of 20 files (`results/audits/`).
6. 100 pytest tests across unit/data/integration/model groups.
7. Machine-readable configs for features, labels, splits, models, safety, experiments.

## 2. What is partially implemented

- **Dataset auditing**: tooling exists and loops over registered files, but CSE-CIC-IDS2018 was
  audited when only 1 of 10 files existed; the other 9 (incl. a 4.05 GB file with a different
  84-column schema containing `Src IP`/`Dst IP`) have never been audited.
- **Report generation**: `scripts/phase1/generate_reports.py` exists, but lines 559/560/591
  *hard-code* `DATA_NOT_AVAILABLE` for CIC-IDS2017 and UNSW-NB15 regardless of manifest state, and
  the generated `transfer_report.md` still names features (`flow_pkts_per_s`, `syn_flag_count`,
  `pkt_len_std`, `fwd_packets_count`) that no longer exist in the registry.
- **Pipeline smoke test**: `xrlids.cli smoke` is documented in `REPRODUCIBILITY.md §3` but now
  raises `KeyError: 'test_metrics'` because the run returns `BLOCKED_FEATURE_INCOMPATIBLE`.
- **Leakage auditing**: 3 of 6 checks genuinely execute; 2 are structurally impossible with the
  current frame (no IP, no timestamp columns are ever passed to the splitter); 1 is asserted.

## 3. Implemented but scientifically unvalidated

- **Policy A (feature dedup) as the default split policy**: removes 33.96% of rows
  (111,414 of 328,110) with `keep='first'` in file order and **no check whether duplicate feature
  vectors carry conflicting labels**. Assumption A-006 correctly lists this as UNVALIDATED.
- **T = 5 "temporal" sequences**: sequences are windows over *file row order* after random
  assignment to splits. No test or artifact establishes that file order is time order, nor what
  an inter-element gap means. `configs/models/lstm_baseline.yaml` itself says
  `construction: null`, `ordering_key: null` — i.e. the config admits the design is undefined
  while `lstm.py` already implements one.
- **Fusion as a contribution**: α=0.30 tuned on validation is methodologically correct, but at the
  reported operating point fusion *reduces* recall from RF's 0.474 to 0.175.
- **SHAP ranking**: 200 explained samples, one seed, no stability run.

## 4. Empirically validated (reproducible from committed artifacts)

Verified in this audit by recomputing from `predictions_test.csv` (43,336 rows):

| Model | metric | recorded | recomputed |
| --- | --- | --- | --- |
| RF | accuracy / ROC-AUC / FPR / recall | 0.6479 / 0.6443 / 0.3002 / 0.4742 | **identical** |
| LSTM | accuracy / ROC-AUC / FPR / recall | 0.7938 / 0.7284 / 0.0169 / 0.1602 | **identical** |
| Fusion | accuracy / ROC-AUC / FPR / recall | 0.7978 / 0.7452 / 0.0162 / 0.1750 | **identical** |

Also validated: dataset hashes (20/20), CIC-IDS2017 per-file row counts (2,830,743 total = published
canonical), UNSW-NB15 partition counts (175,341 / 82,332 = published), CSE-2018 label sets (10/10
files), train-only scaler fit, validation-only α and Platt fitting.

**Scope of that validation:** one file, one day, one attack family (`Infilteration` — 93,063 of
9,970 test positives come from a day whose only attacks are infiltration).

## 5. Documented but not implemented

| Documented claim | Reality |
| --- | --- |
| `PROJECT_STATUS.md`: "Test suite ✅ 101 tests passing" | 100 collected, **17 fail**, 83 pass |
| `REPRODUCIBILITY.md`: "Expected: 67 passed" | stale; same suite fails |
| `REPRODUCIBILITY.md §3` smoke command | crashes with `KeyError: 'test_metrics'` |
| `PROJECT_STATUS.md`: CIC-IDS2017 & UNSW-NB15 `DATA_NOT_AVAILABLE` | both are present, registered and `verified` in the manifest |
| `EXPERIMENT_REGISTRY.md`: "_None yet._ No datasets acquired, no models trained" | 3 experiments, 1 real-data run, 5 registered claims |
| `README.md`: "No dataset is present in the repository, so no detection result exists yet" | 20 files / 7.8 GB present; results exist |
| `DATASET_PROVENANCE.md`: "1 verified real dataset file present" | 20 verified files |
| `phase1_final_report.md` dataset-acquisition rows | hard-coded strings in `generate_reports.py:559-560` |
| `FR-001…FR-032` all `⬜` in `FUNCTIONAL_REQUIREMENTS.md` | most Phase-1 FRs are in fact implemented and tested — the requirements table is stale in the *other* direction |
| `configs/*.yaml` `require_verified_checksums`, `require_status`, `require_frozen` | no code reads or enforces these keys |

## 6. Implemented but not documented

- The **actual** duplicate policy behaviour (exact-duplicate removal in cleaning **plus**
  feature-dedup in the splitter, two different dedup layers) is only visible in code.
- `run_experiment.py` subsample mode (`--sample-limit`, stratified by label, re-ordered by index).
- `verify_files()` exists but is disconnected from the runner.
- The empty-string unicode replacement in `label_mapping.yaml` and its consequences.

## 7. Incorrectly documented (must be corrected, not defended)

1. **UNSW-NB15 reference counts are swapped** in `dataset_registry.yaml`
   (`expected_files` says testing-set = 175,341 and training-set = 82,332; the official UNSW page
   and the actual files are the opposite: training 175,341 / testing 82,332).
2. **Commit hashes inside "generated" reports were hand-edited** by commits `d854a76` and
   `e91a016` ("chore/docs: update commit hash in phase 1 generated reports"). A generated report
   that reports a commit it was not generated from violates the project's own NFR-007.
3. **`phase1_final_report.md` RQ2 answer** ("temporal sequencing effectively filters isolated
   flow-level false alarms") omits that the LSTM misses 84% of attacks (recall 0.160, FNR 0.840).
   The low FPR is obtained by predicting benign almost always.
4. **`phase1_final_report.md` RQ4 answer** ("R10 outperforms the 4-feature contract") compares a
   328,110-row full run against a 2,972-row subsample run — an invalid comparison.
5. **`phase1_final_report.md` RQ3 answer** ("outperforming both individual models") is true for
   ROC-AUC only; at threshold 0.5 fusion is worse than RF on recall by 2.7×.
6. **`transfer_report.md`** feature names do not match the current registry.
7. **`dataset_summary.json`** contains only UNSW (1 of 3 datasets); `label_rejections.csv` contains
   only the 25 CSE repeated-header rows and none of the 33 in `Wednesday-28-02` or 1 in
   `Friday-16-02`.
8. **The stale claim is enforced by a test.** `tests/integration/test_report_generation.py:39`
   asserts that `phase1_final_report.md` contains the literal token `DATA_NOT_AVAILABLE`.
   Fixing the generator's hard-coded status strings will therefore *break* this test — the suite
   currently locks the falsehood in place.
9. **`results/smoke/smoke_R10.json` is a stale artifact.** Running the documented command
   `xrlids.cli smoke --rung R10 --rows 1500` during this audit overwrote it with status
   `BLOCKED_FEATURE_INCOMPATIBLE` (the CIC bug), whereas the committed version records
   `SMOKE_ONLY` with full metrics. The file was restored to its committed state after the audit;
   the discrepancy is recorded here rather than left in the working tree.

## 8. Dataset truth table

| Dataset | Required distribution | Required files | Files present | Exact match? | Source verified? | SHA verified? | Schema audited? | Labels audited? | Ready for research? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CIC-IDS2017 (MachineLearningCSV, UNB/CIC 2017) | 8 day CSVs, 79 cols, 2,830,743 rows, 14 label values | 8 | **8** | ✅ row counts & labels match the published canonical distribution; zip retained at `data/raw/cicids2017_download/csvs/MachineLearningCSV.zip` | 🟡 **third-party mirror (HuggingFace)** — cache metadata proves the download route; manifest records "(UNB)" | ✅ all 8 match manifest; manifest hashes are self-computed (no official digest to compare) | ✅ 8/8 audited | ✅ 8/8, all labels in contract | 🟡 **No — pipeline cannot execute** (column-map/strip bug) |
| CSE-CIC-IDS2018 (Processed Traffic Data, CSE/CIC 2018) | 10 day CSVs, 80 cols (some mirrors 84), 16,233,002 rows | 10 | **10** | ✅ sizes total 6.41 GiB = published distribution; 7 files at the known 1,048,575-row cap; identical 59 repeated-header rows to community copies | 🟡 claimed "AWS Open Data mirror"; **no download record, URL, etag or cache** committed | ✅ all 10 match manifest (self-computed) | 🟡 **1/10 audited** | ✅ 10/10 audited in this audit (all labels covered by contract; 59 repeated-header rows rejected) | 🟡 partly — one day trained; 9 files unaudited by tooling; 4.05 GB file not loadable in 14 GB RAM |
| UNSW-NB15 (UNSW Canberra, 2015 partitioned CSVs) | training 175,341 / testing 82,332, 45 cols, 9 attack cats | 2 CSVs (+LIST_EVENTS) | **2** (LIST_EVENTS absent — metadata only) | ✅ counts match official page exactly; manifest's own reference notes are **swapped** (doc bug) | 🟡 "mirrored", no download record | ✅ both match manifest | ✅ 2/2 audited | ✅ 2/2, `Normal` + 9 categories all mapped | 🟡 — R10 unsupported (4/10 features); only a 4-feature transfer contract is satisfiable |

**Provenance classification.** No file in this repository can be cryptographically associated with an
official source: the manifest hashes were computed from the local bytes (`prepare_dataset.py register`),
which proves *integrity since registration*, not *origin*. Content-level evidence (row counts, label
sets, file sizes, internal zip listing) is strong and consistent with the canonical distributions for
all three datasets. CIC-IDS2017 has a *documented third-party route* (HuggingFace); CSE/UNSW routes
are undocumented.

## 9. Scientific methodology gaps

| Area | Status | Evidence |
| --- | --- | --- |
| Train/validation/test roles | ✅ structurally correct (scaler, α, Platt, threshold candidates all fit on validation) | `pipeline.py`, `run_experiment.py` |
| Test isolation | 🟡 test evaluated once per run, but **model/threshold decisions are not frozen** (D-002/D-003 open), so repeated test exposure will accumulate | `threshold_candidates.json` |
| Split type | ❌ stratified **random** only; no temporal split possible (timestamp never reaches the splitter), no group split used | `SplitConfig.time_column=None`, L-05 not performed |
| Duplicate handling | 🟡 two-layer dedup; no label-conflict analysis; `keep='first'` order-dependent | `splitter.py`, `cleaning.py` |
| Leakage checks | 🟡 L-01/L-02 done (L-02 ≈ exact match), L-03/L-04/L-05 not performed, L-06 asserted | `leakage_report.json` |
| Population definition | ✅ recorded per metric (43,340 RF vs 43,336 LSTM/fusion) | `test_metrics.json` |
| Baseline ladder | ❌ no majority-class, no logistic regression, no decision tree, no gradient boosting — RF vs LSTM vs fusion only | `results/baselines/` empty |
| Multiclass / per-family evaluation | ❌ binary only; family labels preserved but never evaluated | — |
| Uncertainty | ❌ no confidence intervals, no repeated seeds, no variance | — |
| Cross-dataset (6 directions) | ❌ 0 of 6 target evaluations executed | `results/cross_dataset/` empty |
| OOD / unseen attack family | ❌ not started | `results/ood/` empty |

## 10. Machine-learning gaps

- **Result strength.** On the only real full run: RF ROC-AUC 0.644, F1 0.383, balanced accuracy
  0.587; LSTM recall 0.160; fusion recall 0.175 at 0.5. Validation-threshold candidates:
  recall ≥0.95 ⇒ FPR 0.71; FPR ≤0.01 ⇒ FNR 0.85; max-F1 threshold 0.30 gives F1 0.485.
  **This is not yet a defensible detector** — the honest research finding so far is that a 10-feature
  contract on an infiltration-only day is hard, not that the system "detects attacks".
- **RF**: `n_estimators` 100 (config) vs 200 (default/`rf_baseline.yaml`) — two documented values;
  `n_jobs=-1` on 12 cores; artifact `.joblib` **not committed** (`.gitignore` `*.joblib`) so the
  experiment record points at files a cloner does not have.
- **LSTM**: full dense sequence tensor + full-batch validation tensor in RAM; no `pos_weight` /
  class weighting despite 23% attack rate and per-family rarity; `epochs=15, patience=3, hidden=32`
  only in the executed config; CPU-only; best-checkpoint saved but no checkpoint/resume.
- **Fusion**: correct α isolation; no disagreement significance test; no calibration-aware fusion.
- **Calibration**: Platt on validation, Brier/ECE reported — good; no reliability figure, no
  per-class calibration, calibration of *raw* vs *fused* not compared for the operational point.
- **Threshold**: D-003 genuinely open; no cost model exists to close it.
- **SHAP**: RF only; 100/200 sample; no LSTM/fusion/policy explanation; no stability.
- **Explainability of failures**: error analysis is the strongest module — confidence distributions,
  difficulty slices, duplicate-subset analysis, RF↔LSTM disagreement and fusion rescue/degradation
  counts all exist and are populated.

## 11. RL gaps

Nothing exists beyond `configs/models/dqn_baseline.yaml`: no `src/xrlids/rl/`, no environment, no
simulator, no replay buffer, no transition log, no training script, no evaluation against the five
required baselines (Always-ALLOW, Always-BLOCK, fixed threshold, RF policy, fusion policy), no
reward-sensitivity study (A/B/C still marked `TODO`), no `results/dqn/`. The reward table exists as
a hypothesis with `status: hypothesis_not_truth` — honest, but it means **RQ7 has zero evidence**.

## 12. Live-system gaps

No packet capture, no 5-tuple flow assembler, no timeout policy (D-006 open), no live feature
extractor, no parity harness, no `results/realtime/`. Feature parity (RQ8) is therefore entirely
untested, and the parity gate in `INFERENCE_CONTRACT.md` ("one failing feature blocks enforcement")
has nothing to gate. Of the 10 R10 features, 9 are declared `live_available: true` *in metadata
only* — none has ever been produced from packets.

## 13. Safety gaps

- Configs exist and are well thought-out (OBSERVE/DRY_RUN/ENFORCE, fail-closed behaviour,
  protected sources, rollback required) — **but no code implements any of it**.
- `protected_sources.yaml` ships with empty `management_ips`, `gateway_ips`, `protected_subnets`
  (deliberately, to avoid committing personal addresses) → an ENFORCE run today would have **zero
  protected hosts**.
- No tests exist for protected-host, cooldown, rollback, dry-run (tests/system is empty).
- Default mode is OBSERVE in config — good — but nothing consumes the config.

## 14. Deployment gaps

No `services/`, no compose files (`deployment/**/.gitkeep`), no runbook (`docs/operations/*` all ⬜),
no health checks, no environment documentation beyond `REPRODUCIBILITY.md` venv setup. The system
today is "a Python package plus scripts", not a runnable system.

## 15. Resource and memory issues (measured on the actual machine)

Machine: **14 GiB RAM (≈8.3 GiB available), 12 CPU, 495 GB disk, CPU-only torch.**

| Operation | Current behaviour | Projection |
| --- | --- | --- |
| Load CSE `Thuesday-20-02-2018.csv` (4,054,925,350 B) | `pd.read_csv(low_memory=False)` — whole file in RAM | 7.95 M rows × 84 cols ⇒ **>14 GiB → OOM**; this file cannot be processed by the current pipeline at all |
| Load largest CIC file (225 MB, 692 k rows) | fine | ✅ |
| Cleaning | `frame.copy()` twice + `drop_duplicates` | ≈2–3× frame size transiently |
| Policy-A dedup | `frame.duplicated(subset=…)` over all features | another full-frame copy |
| LSTM sequences | `np.asarray(list_of_windows)` then `torch.tensor(...)` full copy + full-batch validation tensor | R10 on 216 k rows ≈ 216 k×5×10×8 B ≈ 87 MB ×3 copies — fine here; on a 7.9 M-row file ≈ 3.2 GB ×3 = **OOM** |
| SHAP | 100×200 samples | ✅ trivial |

**Conclusion:** the pipeline loads entire datasets into memory with multiple full-frame copies.
The only dataset in the repo that it provably cannot run on is the one it most needs for coverage
(Tuesday 20-02). Required architecture: chunked `read_csv` (usecols + chunksize), streaming row
accounting, memory-mapped/downsampled sequence generation, per-chunk feature materialisation and
**documented** sampling where full-data training is infeasible.

## 16. Reproducibility gaps

1. Model artifacts (`*.joblib`, `*.pt`) are gitignored → experiment records reference missing files.
2. Generated reports carry hand-edited commit hashes (`d854a76`, `e91a016`).
3. `generate_reports.py` hard-codes dataset status instead of reading the manifest.
4. `results/audits/dataset_summary.json` and `label_rejections.csv` are stale (1 dataset, 1 label).
5. Test-failure state means `REPRODUCIBILITY.md §2/§3` do not do what they say.
6. No lockfile (`requirements.txt` pins top-level only; no hashes).
7. Dataset acquisition route is not recorded as a command/URL (except CIC's HF cache, which is
   untracked).
8. Two experiments are subsamples; only one is full-data — the registry does not distinguish them
   at a glance (the JSON status does, the Markdown registry does not).

## 17. Professor / viva risk register

| Professor's question | Can the repo answer it today? | Why not |
| --- | --- | --- |
| Why these three datasets? | 🟡 | provenance doc exists but status lines are stale and provenance route undocumented |
| Why flow-level detection? | 🟡 | stated in scope, never argued against packet/other alternatives |
| Why these features / why R10? | ❌ | D-002 open, gate answers `unverified` for Q7/Q8 on every feature |
| How do you know there is no leakage? | 🟡 | L-01/L-02 real; L-03/04/05 never executed; no temporal/group argument |
| How did you train it? | ✅ | fully documented, artifacts + seeds + commit |
| Why is the LSTM necessary? | ❌ | recall collapse (0.16) is not addressed anywhere |
| Why fusion? | ❌ | report says "outperforms"; at 0.5 it loses recall vs RF |
| What happens when the model is wrong? | ✅ | error analysis module is strong |
| What does SHAP actually tell you? | ✅ | caveats are explicit and correct |
| Why use reinforcement learning? | ❌ | no policy code, no baseline comparison |
| How was the DQN trained? | ❌ | cannot be answered |
| How do packets become model features? | ❌ | no live path, no parity evidence |
| What prevents blocking legitimate traffic? | 🟡 | policy config exists; no code, no tests, empty protected list |
| Can I reproduce your result? | 🟡 | predictions→metrics reproduce exactly; end-to-end rerun fails (17 tests, CIC bug) |
| Why is accuracy 0.79 meaningful under 23% attack prevalence? | ❌ | no document frames the prevalence/imbalance honestly |
| What are the limitations? | 🟡 | scattered across claims registry and assumptions, no consolidated limitations doc |

---

## 18. Critical blockers (fix before any further empirical work)

1. **CIC-IDS2017 pipeline broken** — column map with leading spaces vs stripped headers
   (reproduced; also breaks `xrlids.cli smoke`, 13 tests).
2. **17/100 tests failing** — documentation claims 101 passing.
3. **9 of 10 CSE-2018 files never audited** by tooling (incl. an 84-column file with raw IPs).
4. **Generated-report integrity** — hard-coded statuses and hand-edited commit hashes.
5. **Experiment registry / README / PROJECT_STATUS / DATASET_PROVENANCE** contradict the manifest.
6. **UNSW manifest reference counts swapped.**
7. **Memory ceiling** — the largest CSE file cannot be loaded on this machine.
8. **No baseline ladder, no cross-dataset target evaluation, no RL, no live path, no safety code** —
   i.e. RQ4, RQ5 (partially), RQ7, RQ8, RQ9, RQ10 have zero or near-zero evidence.

---

## 19. Exact remaining build requirements

See the authoritative specification: [`../01_REQUIREMENTS/END_TO_END_BUILD_SPEC.md`](../01_REQUIREMENTS/END_TO_END_BUILD_SPEC.md)
(requirements BS-001…BS-160 with validation methods and acceptance criteria) and its gap register
(GAP-01…GAP-48, severity-tagged).
