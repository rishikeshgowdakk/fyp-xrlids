# CONTRIBUTING

## The most important rule

Every important claim must be reproducible. Before any result enters this repository,
the answer to all of the following must exist **inside the repository**:

```text
Which dataset?        Which exact files?      Which dataset version?
Which rows?           Which cleaning ops?     Which split?
Which features?       Which preprocessing?    Which model version?
Which random seed?    Which threshold?        Which prediction file?
Which confusion matrix?  Which formula?       Which code?   Which Git commit?
```

```text
NO RESULT WITHOUT ARTIFACT
NO ARTIFACT WITHOUT CODE
NO CODE EXPERIMENT WITHOUT CONFIG
NO METRIC WITHOUT TEST POPULATION
NO FINAL CLAIM WITHOUT EVIDENCE
```

## What the agent/contributor may decide without asking

File names, Python implementation details, class organisation, refactoring, test naming,
logging format, error messages, non-research code style, dependency organisation —
provided they do not alter experimental meaning.

## What must NOT be decided without the user

Dataset replacement or removal, label reinterpretation, feature-contract changes,
primary-metric changes, train/test methodology changes, threshold-objective changes,
attack-taxonomy changes, reward-function changes, live enforcement policy, firewall scope,
security-sensitive deployment changes, or claiming a failed experiment succeeded.

When in doubt, use the blocked-on-research-decision format (§84 of the build spec) and stop.

## Git workflow

Every logical milestone:

```text
git status → git diff → tests → experiment check → commit
```

Commit messages are scoped and descriptive (never one giant "finished project"):

```text
phase1: add dataset provenance
phase1: implement CIC audit
phase1: freeze label contract
phase1: add canonical feature schema
phase1: add leakage audit
```

## Adding an experiment

1. Allocate an experiment ID from [`docs/experiments/EXPERIMENT_REGISTRY.md`](docs/experiments/EXPERIMENT_REGISTRY.md).
2. Copy [`docs/templates/EXPERIMENT_CARD_TEMPLATE.md`](docs/templates/EXPERIMENT_CARD_TEMPLATE.md) into `docs/experiments/`.
3. Add the machine-readable config under `configs/experiments/`.
4. Run it and emit machine-readable results into `results/`.
5. Register any resulting claim in [`docs/03_DECISIONS/CLAIMS_REGISTRY.md`](docs/03_DECISIONS/CLAIMS_REGISTRY.md).
6. If a research decision was required, open a Decision ID first — do not decide silently.

## Documentation levels

Every result needs all three: human-readable Markdown, machine-readable JSON/YAML/CSV,
and executable code that regenerates it.
