# DATASET PROVENANCE

Status: **acquisition workflow complete; datasets NOT acquired.**
Authoritative machine record: [`../../data/manifests/dataset_registry.yaml`](../../data/manifests/dataset_registry.yaml)

## Provenance declared

| Dataset | Source | Official page | Version declared | License |
| --- | --- | --- | --- | --- |
| CIC-IDS2017 | CIC, University of New Brunswick | https://www.unb.ca/cic/datasets/ids-2017.html | as-published-2017 | research use per CIC terms (to confirm on page) |
| CSE-CIC-IDS2018 | CSE + CIC, UNB | https://www.unb.ca/cic/datasets/ids-2018.html | as-published-2018 | research use per CIC/CSE terms (to confirm) |
| UNSW-NB15 | UNSW Canberra Cyber | https://research.unsw.edu.au/projects/unsw-nb15-dataset | as-published-2015 | research use per UNSW terms (to confirm) |

## Acquisition constraint (checked 2026-09-30)

The historical primary mirror `iscxdownloads.cs.unb.ca` **does not resolve from this
network** — DNS returns NXDOMAIN for both `iscxdownloads.cs.unb.ca` and `download.unb.ca`.
Controls performed at the same time: `google.com` → 200, `github.com` → 200, `unb.ca` → 200,
PyPI download → succeeded. So this is a hostname/mirror availability problem, **not** a
general network failure. The official dataset *pages* are reachable; the download *hosts*
are not, from here.

Consequence: acquisition requires **manual download** by the project owner (or an
authorised mirror), followed by registration + verification. This is recorded in the
manifest (`acquisition_note`) rather than worked around.

## What was NOT done (deliberately)

- No checksum was invented or hand-entered. `sha256` fields are only written by
  `prepare_dataset.py register`, which hashes the actual bytes on disk.
- No file was marked `verified` — nothing is present to verify.
- No substitute dataset, sample, or mirror was silently accepted.
- `expected_files` lists the filenames as published by the sources; mirrors that rename
  files must be registered with a note, never passed off as identical content.

## Expected files

| Dataset | Expected CSVs | Reference notes recorded |
| --- | --- | --- |
| CIC-IDS2017 | 9 machine CSVs (one per capture day, CICFlowMeter) | label-header and duplicate-row artifacts to be re-verified by audit |
| CSE-CIC-IDS2018 | 8 day CSVs (names vary across mirrors) | heterogeneous per-file schemas expected; each file audited independently |
| UNSW-NB15 | testing-set, training-set, LIST_EVENTS | published reference row counts (175,341 / 82,332) recorded for later verification — NOT audit results |

## How to complete acquisition

```bash
python scripts/phase1/prepare_dataset.py instructions   # exact per-file instructions
# ... place files in data/raw/<dataset>/ ...
python scripts/phase1/prepare_dataset.py register --dataset <key> --all
python scripts/phase1/prepare_dataset.py verify   --dataset <key>
python scripts/phase1/03_run_audit.py             # schema + audit + label accounting
```

States used by the manifest: `not_acquired | partial | available | verified | failed`
(files: `expected | registered | verified | mismatch`). Nothing advances a state without
the corresponding evidence.
