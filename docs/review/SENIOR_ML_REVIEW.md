# Senior ML Review — XRL-IDARS Phase 1 (Detection Training, Splits & Artifacts)

- **Reviewer role:** Senior ML Engineer (detection / applied research)
- **Repository:** `fyp-xrlids` — XRL-IDARS v1
- **Reviewed commit (HEAD at review time):** `be8b8db` (`feat: add web dashboard server ...`)
- **Artifacts reviewed:** `results/experiments/EXP-P1-*`, `models/registry/`, `src/xrlids/{splitting,preprocessing,models,features,datasets}`, `scripts/phase1/run_experiment.py`, `configs/`
- **Verification performed:** full test suite run (all pass, 0 failures), model artifacts loaded and executed end-to-end, per-family and leakage artifacts parsed.

> This document answers four questions directly: (1) is the model trained correctly, (2) are train/test splits sound, (3) are the artifacts trustworthy, (4) where is the significant performance drop and how do we raise accuracy — and whether any dataset should be removed.

> **Resolution status (2026-10-17).** Retained as the historical review that triggered a repo-wide correction pass. Current state of the tracked defects:
> - **A1 (empty `hyperparameters.rf`)** — resolved: `hyperparameters.rf`, `model.primary_baseline.params`, and `model.models_evaluated.random_forest.params` all carry the full RF config in the canonical records.
> - **A2 (UNSW labelled `R10` but trained on R4)** — resolved: registry, experiment records, and the runner now record the effective `R4` contract and its schema hash.
> - **A3 (single-seed artifacts vs `seeds: [42,123,456]`)** — resolved (2026-10-17): the full 3-seed sweep was executed across all three benchmarks (`seed_42/123/456/`); seed 42 reproduces the frozen artifacts exactly and the headline metrics are seed-stable (mean ± std in `reports/generated/multi_seed_report.md`). Frozen headline artifacts remain single-seed by design; reproduction commands state `--seeds 42`.
> - **A4 (test-count drift)** — resolved: every document reports the verified 408-test suite.
> - **A5 (artifacts pinned to their run commit)** — accepted: the recorded `git_commit` is the run-time fact; generated reports now reference the commit they were generated at.
> - **A6 (native vs aligned UNSW values)** — resolved: all UNSW tables use the aligned values (RF 0.8590 / 0.8548, ROC-AUC 0.9487), matching the registry.
> - **A7 (row-level split optimism / no temporal validation)** — addressed (2026-10-20): `EXP-P1-CSE2018-TEMPORAL-R10-001` trains on 14–20 Feb and evaluates once on 22 Feb–2 Mar using the real CSE `Timestamp`; L-01/L-02/L-05 pass. RF F1 falls from 0.8861 (random) to **0.0113** (temporal), bot recall from 99.17% to 0.09%, and infiltration from 10.70% to 0.94%; the random-split result is an in-domain upper bound. Comparison: `reports/generated/temporal_split_report.md`.
> - **A8 (no uncertainty intervals on detector metrics)** — addressed (2026-10-20): per-seed 95% bootstrap CIs are published in `reports/generated/bootstrap_ci_report.md` with machine-readable `bootstrap_cis.json` per experiment.

---

## 0. Executive verdict

| Area | Verdict | Confidence |
| --- | --- | --- |
| Training mechanics (fit/transform isolation, early stopping, seeding) | **Correct** | High |
| Split mechanics (disjoint, stratified, deterministic, replayable) | **Correct** | High |
| Split *experimental design* (can it support a deployment claim?) | **Optimistic / limited** | High |
| Artifact completeness & loadability | **Strong** | High |
| Artifact *provenance consistency* | **Has defects** — fix required | High |
| In-domain headline accuracy (RF/LSTM/Fusion) | **Real, but inflated by row-level splitting and DoS-dominated test sets** | High |
| Detection of stealthy attacks (Infiltration/XSS/Web-BF) | **Broken** (2.8%–16% recall) | High |
| Cross-dataset generalization | **Absent** (52%–95% F1 collapse) — expected | High |

**One-line summary:** the *code is trained correctly*, the *splits are mechanically clean*, but the *scientific framing overstates* what row-level random splits on duplicate-heavy, DoS-dominated benchmarks can prove. The real project risks are (a) stealthy-attack blind spots, (b) row-level leakage optimism, (c) UNSW being blended into headline claims it cannot support, and (d) several provenance/documentation inconsistencies.

---

## 1. Is the model trained correctly?

**Yes — the training mechanics are sound.** Concretely verified in code and artifacts:

| Control | Where | Status |
| --- | --- | --- |
| Scaler / imputation fit on **train only** | `src/xrlids/preprocessing/pipeline.py` — `Preprocessor.fit(train_df)` accepts only training data | ✅ Correct by construction |
| Validation used only for hyperparameter/threshold/α selection | `scripts/phase1/run_experiment.py` (`tune_fusion_alpha` on validation) | ✅ Correct |
| Test touched once for final metrics | runner evaluates test after all selection | ✅ Correct |
| Sequence windows cannot cross split boundaries | `src/xrlids/models/lstm.py` — `build_sequences(split=...)`, `assert_no_boundary_crossing` | ✅ Correct |
| Determinism | `set_global_seeds(seed)` + `random_state` propagated | ✅ Verified |
| Early stopping / best-checkpoint restore | `LSTMDetector.fit` restores `best_state` | ✅ Correct |
| Class imbalance handling for RF | `class_weight: balanced_subsample` | ✅ Present |

Radom-Forest hyperparameters actually baked into the CIC artifact: `n_estimators=100, max_depth=16, min_samples_leaf=2, class_weight=balanced_subsample, random_state=42`.

**Artifacts load and predict.** I loaded `random_forest.joblib` + `preprocessor.joblib` from `EXP-P1-CIC2017-R10-001`; the preprocessor exposes the frozen 10-feature R10 contract and the RF returns an uncalibrated tree-vote score; Platt calibration is a separate validation-fit artifact, not a property of the raw score. The artifact set is complete per experiment (model, preprocessor, split manifest, leakage report, metrics, per-family CSV, calibration, threshold candidates, SHAP, predictions).

### Training weaknesses (not bugs, but limitations)

1. **Single seed for all headline runs.** The full multi-file runs record `random_seed = 42` with no `seed_*` output directories. There are no confidence intervals on the headline F1 numbers as published. The config (`configs/experiments/p1_cicids2017_r10.yaml`) now declares `seeds: [42, 123, 456]`, but the committed artifacts predate/lag that. → **Run 3+ seeds and report mean ± std.**
2. **LSTM is deliberately small** (hidden 32, 2 layers, 15 epochs, patience 3) and gets the biggest win on CSE — yet on CSE the tuned fusion α collapses to 0.00 (pure LSTM). That means **the "RF+LSTM fusion" claim is really an LSTM-only model on the largest, most important benchmark.** Present it that way.
3. **Fusion α tuned on ROC-AUC**, then only α=0.5 / 0.0 / 0.6 fall out. On CSE α=0 means RF contributes nothing — a signal that RF and LSTM are not actually complementary there.
4. **Threshold frozen at 0.50** while D-003 is open. All reported recall/FPR are at a neutral threshold that is not the operating point the response system will use. Recall on rare attacks is threshold-sensitive.

---

## 2. Are the train/test splits correct?

### Mechanically: yes

- 60/20/20, `stratified_random`, `seed=42`, deterministic, manifest-hashed.
- Feature-level deduplication **before** splitting removes identical feature vectors across the whole population, so exact (L-01) and rounded near-duplicate (L-02) overlap is **0** across train/val/test.
- L-06 (sequence overlap) enforced structurally.
- Policy B comparison (retaining duplicates) was run and **failed leakage** — good, that control validates the mechanism.

### Scientifically: the design cannot support a deployment claim

The split is a **row-level random split**, not a **host-disjoint** or **temporal** split. Consequences:

1. **Near-duplicate / burst leakage remains.** Exact vectors are removed, but a DoS burst or botnet beacon produces thousands of *near*-identical flows. Row-level splitting puts neighbours from the same attack burst in both train and test → in-domain metrics are **optimistically biased**. This is the single largest scientific caveat and it applies to all three datasets.
2. **The leakage audit's strongest checks were not run.** From `results/experiments/EXP-P1-CIC2017-R10-001/leakage_report.json`:
   - `L-03 group_overlap` → `not_performed`
   - `L-04 source_ip_overlap` → `not_performed`
   - `L-05 temporal_overlap` → `not_performed`
   So only the two weakest checks actually passed. "Leakage: pass" in the summary should be read as "exact-duplicate leakage: pass".
3. **Root cause is (partly) the data, not the pipeline.** I confirmed the CIC-IDS2017 files shipped here have **79 columns and no Source IP / Destination IP / Timestamp**. So host- or time-grouped splitting is genuinely impossible *for this distribution of CIC*. The `docs/phase1/SPLIT_METHODOLOGY.md` rationale is honest about this.
4. **But CSE-CIC-IDS2018 *does* have a `Timestamp` column (col 3 of 80).** A **temporal (by-day / by-time-window) split is feasible for CSE** and should be added — it is far stronger evidence than row-level random and directly addresses the duplicate-burst leakage on the flagship dataset.

**Recommendation:** keep the row-level split as a "same-distribution performance" result, but add:
- a **temporal split for CSE** (`Timestamp` exists), and
- a **grouped split by attack-instance / source** wherever a key exists,
and report the row-level numbers side-by-side with the honest ones.

---

## 3. Are the artifacts trustworthy?

**Loadable and complete: yes. Provenance-consistent: not yet.** Defects found during review:

| # | Issue | Evidence | Severity |
| --- | --- | --- | --- |
| A1 | `hyperparameters.rf` is **empty `{}`** in the experiment record, while the real RF config lives elsewhere in the same file | `EXP-P1-CIC2017-R10-001/experiment_record.json` | Medium — reproducibility |
| A2 | UNSW models registered as **`feature_contract: R10`** but were trained on **R4** | `models/registry/registry.yaml` vs `reports/generated/transfer_report.md` | **High** — wrong contract label |
| A3 | Config declares `seeds: [42,123,456]` but artifacts are **single-seed** | `configs/.../p1_cicids2017_r10.yaml` vs `random_seed=42`, no `seed_*` dirs | Medium |
| A4 | Test-suite count inconsistent across docs | `phase1_final_report.md` says **216**; `README.md`/`PROJECT_STATUS.md` say **386**; I ran the suite and **388 pass** | Low |
| A5 | Artifacts pinned to a **stale commit** | record `git_commit = fa370a9` vs HEAD `be8b8db` | Low–Medium |
| A6 | `docs/final/comparison_report.md` (generated) shows UNSW RF `0.8548/0.8590` in one place and `0.8546/0.8588` elsewhere | native vs aligned populations, not labelled consistently | Low |

None of these invalidate the models, but A2 must be fixed before any external reader trusts the registry, and A1/A3 undermine the "reproducible" claim.

---

## 4. How each dataset is actually trained (summary)

| Dataset | Raw rows | Modeling rows | Contract | Files | Split | Test rows | Headline (Fusion F1) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CIC-IDS2017 | 2,830,743 | 1,779,322 | **R10** (10 feat) | 8 day CSVs | row-level stratified 60/20/20 | 355,833 aligned | 0.9745 (α=0.50) |
| CSE-CIC-IDS2018 | 16,233,002 | ~ (10 files) | **R10** | 10 day CSVs | row-level stratified 60/20/20 | 1,662,419 aligned | 0.9603 (α=0.00 → pure LSTM) |
| UNSW-NB15 | 257,673 | 122,520 | **R4** (4 feat fallback) | 2 published files | row-level stratified 60/20/20 | 24,496 aligned | 0.8970 (α=0.60) |

Cleaning is aggressive and reconciled: CIC drops ~194k exact duplicates, ~536k feature duplicates, and **~319,537 rows removed as label-conflicting vectors** (the same feature vector appears with both BENIGN and attack labels). That last removal is scientifically important and correct, but it means **~18% of CIC rows are intrinsically unlabelable by these features** — a direct symptom of the payload-blind problem in §5.

> Note: the UNSW "R10-MULTI" experiment name is misleading — it runs the **R4** contract. Rename or relabel it.

---

## 5. Where is the significant drop? (the real story)

**Aggregate accuracy is dominated by a few easy, high-volume attacks. The drop is on stealthy, low-footprint, payload-hidden attacks.** This is the finding that matters.

### CIC-IDS2017 — Random Forest, test set

| Family | Test support | Recall | Error |
| --- | ---: | ---: | ---: |
| DDOS | 25,347 | 0.9970 | 0.3% |
| DOS HULK | 33,074 | 0.9976 | 0.2% |
| DOS GOLDENEYE | 2,037 | 0.9617 | 3.8% |
| DOS SLOWLORIS | 901 | 0.9623 | 3.8% |
| FTP-PATATOR | 897 | 0.9967 | 0.3% |
| SSH-PATATOR | 648 | 0.9846 | 1.5% |
| PORTSCAN | 320 | 0.9906 | 0.9% |
| BOT | 196 | 0.9592 | 4.1% |
| **WEB ATTACK - BRUTE FORCE** | **258** | **0.1589** | **84.1%** |
| **WEB ATTACK - XSS** | **108** | **0.0278** | **97.2%** |
| **WEB ATTACK - SQL INJECTION** | **3** | **0.0000** | **100%** |
| **INFILTRATION** | **8** | **0.0000** | **100%** |
| HEARTBLEED | 3 | 0.6667 | 33.3% |

- DoS Hulk + DDoS = **58,421 / 64,820 = 90%** of all test attacks. The 0.95 F1 is essentially a **DoS detector score**.
- The three genuinely dangerous families (Infiltration, XSS, Web-Brute-Force, SQLi) have **2.8%–15.9% recall**.

### CSE-CIC-IDS2018 — the largest, most operationally relevant drop

| Family | Test support | Recall | Error |
| --- | ---: | ---: | ---: |
| **INFILTERATION** | **7,027** | **0.1070** | **89.3%** → **6,275 missed attacks** |
| SQL INJECTION | 15 | 0.7333 | 26.7% |
| BRUTE FORCE - WEB | 49 | 0.9184 | 8.2% |
| BRUTE FORCE - XSS | 22 | 0.9545 | 4.5% |
| (DoS/DDoS families) | — | 0.98–1.00 | <2% |
| BENIGN (FPR) | 1,475,298 | — | 2.59% false alarms |

CSE's Infiltration drop is the **single largest absolute miss in the project**: 6,275 real intrusions classified benign. Here the LSTM helps (F1 0.8861 → 0.9603, FPR 2.59% → 0.26%), but the *aggregate* gain is still driven by benign false-alarm suppression, not by rescuing Infiltration.

### UNSW-NB15 — weakest domain and highest false-alarm rate

| Family | Test support | Recall | Error |
| --- | ---: | ---: | ---: |
| **Normal (FPR)** | 13,476 | — | **19.3% false alarms** |
| **Fuzzers** | 3,187 | 0.7898 | 21.0% |
| **Analysis** | 103 | 0.7767 | 22.3% |
| **Backdoor** | 83 | 0.8434 | 15.7% |
| Shellcode | 201 | 0.9104 | 9.0% |
| Reconnaissance | 1,373 | 0.9993 | 0.1% |

Only 4 features (no TCP flags, no packet-length std), ~19% false-positive rate on benign traffic. This domain is **not comparable** to CIC/CSE and must not be averaged into a single headline.

### Cross-dataset transfer — the systemic drop

Every one of the 6 transfer directions collapses: **ΔF1 between −0.52 and −0.95**, UNSW-involving transfers with FPR up to 68.6%. This is expected (no domain adaptation) and is correctly framed in `transfer_report.md`. It is a *finding*, not a bug.

---

## 6. Root causes of the drops

1. **Payload blindness.** R10 features are coarse flow statistics (duration, rates, packet-length mean/std, TCP flag counts). Brute-force, XSS, SQLi and Infiltration are distinguished by *payload content and application-layer behavior*, which these features deliberately do not observe. The CIC cleaning step discarding **319,537 label-conflicting vectors** is direct proof the features cannot separate those flows.
2. **Extreme support imbalance.** Rare families have 3–258 test samples. Even a perfect model cannot demonstrate recall on 3 samples; 0/3 and 0/8 are noise, not evidence of failure (though the *pattern* across families is real).
3. **Row-level split optimism.** Near-duplicate burst flows inflate in-domain scores (§2).
4. **Single small LSTM + fusion collapse.** On CSE the RF adds nothing (α=0); on CIC the fusion rescue is mostly false-alarm suppression.
5. **Domain shift + exporter differences.** CICFlowMeter vs Argus/Bro feature semantics and timeouts (documented as a hypothesis in the transfer report) drive the transfer collapse.

---

## 7. How to increase accuracy — prioritized

### Tier 1 — do these first (cheap, high impact, honest)

1. **Add a temporal split for CSE-CIC-IDS2018** using its `Timestamp` column (train on earlier days, test on later days) and a grouped split where an instance key exists. Publish those numbers **beside** the row-level numbers. This is the biggest credibility upgrade available and requires no new data.
2. **Report per-family with support and CIs, and never quote aggregate F1 alone.** Add balanced accuracy / macro-F1 as the primary headline for imbalance, and mark families with `support < 100` as `INSUFFICIENT_SUPPORT` rather than reporting 0% recall.
3. **Fix the evaluation honesty issue:** reframe "test accuracy 0.98" as "same-distribution, row-level, DoS-dominated". Update README/PROJECT_STATUS to state this explicitly.
4. **Run 3 seeds** (`--seeds 42 123 456`) for the three headline benchmarks; report mean ± std. The runner already supports this.

### Tier 2 — accuracy work that actually moves the needle

5. **Escalate the feature contract for the stealth families.** Run the already-planned **R15/R20** sweep and add Inter-Arrival-Time (IAT mean/std/max/min) and TCP flag-ratio features. CIC-IDS2017's raw 79 columns already contain `Flow IAT Mean/Std/Max/Min` — they are simply not in R10. This is the most direct route to Web-Brute-Force/XSS recall.
6. **Targeted class weighting / focal loss for rare families.** RF already uses `balanced_subsample`; add a class-weighted / focal LSTM loss and quantify recall on the rare families specifically.
7. **Threshold tuning under an operational cost matrix (close D-003).** Lowering τ from 0.50 recovers INFILTRATION/XSS recalls at a controlled FPR. Do it on validation, report the operating point, and stop presenting a single neutral threshold as the result.
8. **Hierarchical / one-vs-rest head for rare families.** A binary "attack vs benign" model hides rare families; a second-stage family classifier re-ranks them.
9. **Do not use SMOTE/oversampling before splitting.** If used, apply train-fold-only and re-audit leakage.

### Tier 3 — only if generalization is a real goal

10. **Domain adaptation** (CORAL / DANN / importance weighting) or per-domain recalibration for transfer. Otherwise keep transfer results as a *negative finding* and stop implying the detector is portable.
11. **Use richer UNSW-NB15 features.** UNSW ships 40+ columns (`sload`, `dload`, `sjit`, `djit`, `sttl`, `dttl`, IAT fields). The 4-feature fallback throws away almost all of it. A fuller UNSW-native contract would make the UNSW numbers meaningful.

---

## 8. Should any dataset be removed?

**No dataset should be deleted outright. But the headline framing must be corrected.**

| Dataset | Recommendation | Why |
| --- | --- | --- |
| **CIC-IDS2017** | **Keep** as the primary in-domain benchmark | Core R10 dataset; but no timestamp/IP → row-level only |
| **CSE-CIC-IDS2018** | **Keep — promote** to the strongest evidence | Has `Timestamp` → supports the temporal split; largest population; exposes the Infiltration drop |
| **UNSW-NB15** | **Keep, but demote to *auxiliary* — never blend into a headline average** | Different feature semantics (NetFlow/Argus), only 4 features, ~19% FPR; R4 contract is not comparable to R10 |

**What *should* be removed or re-labelled:**
- **Remove the "R10" label from UNSW artifacts** (registry currently says R10; it was R4). This is a correctness fix.
- **Remove ultra-rare families from per-family *claims*, not from the data.** CIC `INFILTRATION` (8 test), `SQL INJECTION` (3), `HEARTBLEED` (3); CSE `SQL INJECTION` (15). Merge them into an `OTHER_RARE` bucket or mark `INSUFFICIENT_SUPPORT`. Data stays; the misleading per-family recall numbers go.
- **If a single "model accuracy" number must be quoted, quote it per-dataset and per-contract** — never average CIC/CSE/UNSW into one figure.

---

## 9. Documentation inconsistencies to fix

1. `reports/generated/phase1_final_report.md`: "216 passing tests" → should be **388** (verified). Same file lists PyTorch `2.14.0` — re-verify the intended claim; the installed version **is** `2.14.0+cpu`, so this is consistent, but 216 vs 386/388 is not.
2. `README.md` / `PROJECT_STATUS.md`: "386 tests" vs actual **388**.
3. `models/registry/registry.yaml`: UNSW `feature_contract: R10` → should be `R4`.
4. `EXP-P1-UNSWNB15-R10-MULTI-001` name implies R10; it runs R4. Rename for clarity.
5. `experiment_record.json`: `hyperparameters.rf` empty; `git_commit` stale vs HEAD.
6. `README.md` says reuse only requires `data/demo/sample_traffic.pcap` + `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib` — fine, and I confirmed both load, but the RF requires the matching `preprocessor.joblib` (feature order/scaling). Document the dependency.

---

## 10. Prioritized action plan

| Priority | Action | Effort | Impact |
| --- | --- | --- | --- |
| P0 | Fix registry contract labels (UNSW → R4) and empty/ stale provenance | S | Correctness |
| P0 | Reframe headline metrics as row-level, DoS-dominated; add support + macro-F1 | S | Credibility |
| P0 | Mark ultra-rare families `INSUFFICIENT_SUPPORT` | S | Credibility |
| P1 | Temporal split for CSE (Timestamp) + report alongside row-level | M | High |
| P1 | 3-seed runs with mean ± std | M | High |
| P1 | Close D-003 with an operational threshold | M | High |
| P2 | R15/R20 feature sweep incl. IAT + flag ratios | L | High (stealth recall) |
| P2 | Rare-family focal loss / class weighting + OVR head | M | Medium–High |
| P3 | Domain adaptation for transfer | L | Only if portability is a goal |
| P3 | Fuller UNSW-native feature contract | M | Medium |

---

## Appendix — evidence index

- Splits/leakage: `results/experiments/EXP-P1-CIC2017-R10-001/{split_manifest,leakage_report}.json`
- Metrics: `results/experiments/EXP-P1-*-R10-*/{test_metrics.json,per_family_metrics.csv,model_comparisons.json}`
- Cleaning/accounting: `EXP-P1-CIC2017-R10-001/experiment_population.json`
- Transfer: `reports/generated/transfer_report.md`
- Registry: `models/registry/registry.yaml`, `models/fusion/fusion_weights.json`
- Raw schema evidence: CIC-IDS2017 = 79 cols (no IP/timestamp); CSE-CIC-IDS2018 = 80 cols incl. `Timestamp`.
