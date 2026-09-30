# CHANGELOG

All notable changes to `xrlids-v1` (project XRL-IDARS v2).

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Entries are added per logical milestone, matching the `phaseN: <summary>` commit convention.

## [Unreleased]

### Added
- Initial repository structure (configs, docs, data, models, results, reports, src, services, scripts, tests, deployment).
- Project governance layer: project scope, research questions (RQ1–RQ10), system objectives,
  functional and non-functional requirements.
- Decision log with open research decisions D-001…D-006.
- Claims registry (empty of verified claims — by design at project start).
- Assumption registry with initial assumptions A-001…A-004.
- Dataset registry skeleton for CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15 (checksums pending acquisition).
- Feature registry skeleton with R10/R15/R20 rungs marked as provisional.
- Experiment registry and experiment-card / model-card / failure-report / decision templates.
- Label mapping and split config skeletons.
- Reproducibility guide skeleton.

### Notes
- No datasets have been acquired and no models trained: no metrics exist yet.
- Historical results from the previous XRL-IDARS repository are quarantined in
  `docs/04_QUESTIONS/HISTORICAL_RESULTS.md` and labelled *not reproduced*.
