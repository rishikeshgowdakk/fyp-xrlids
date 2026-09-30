# Dataset Provenance and Manifest Report (generated)

Status: `VERIFIED` (real files checked via SHA-256 and row/column counts).

| Dataset | Status | Files Found | Rows | Columns | SHA-256 (Primary) |
| --- | --- | --- | --- | --- | --- |
| **CIC-IDS2017** (`cicids2017`) | `DATA_NOT_AVAILABLE` | 0 | N/A | N/A | N/A |
| **CSE-CIC-IDS2018** (`cse_cic_ids2018`) | `AVAILABLE (VERIFIED)` | 1 | N/A | N/A | `b0534c5d7d8b41e0...` |
| **UNSW-NB15** (`unsw_nb15`) | `DATA_NOT_AVAILABLE` | 0 | N/A | N/A | N/A |

## Detailed Acquisition and Placement Status

### 1. CSE-CIC-IDS2018
- **Status**: `AVAILABLE` and `VERIFIED`.
- **Primary File**: `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (107,842,858 bytes, 331,125 rows, 80 columns).
- **SHA-256**: `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`.
- **Location**: `data/raw/cse_cic_ids2018/`.
- **Provenance**: Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (CIC).

### 2. CIC-IDS2017
- **Status**: `DATA_NOT_AVAILABLE`.
- **Note**: Primary mirror `iscxdownloads.cs.unb.ca` is unreachable (NXDOMAIN).
- **Action to Activate**: Download `GeneratedLabelledFlows` CSV files manually from official UNB mirror and place into:
  ```bash
  data/raw/cicids2017/<csv_filename>.csv
  python scripts/phase1/prepare_dataset.py register --dataset cicids2017 --file data/raw/cicids2017/<csv_filename>.csv
  ```

### 3. UNSW-NB15
- **Status**: `DATA_NOT_AVAILABLE`.
- **Action to Activate**: Place official UNSW-NB15 CSV files into:
  ```bash
  data/raw/unsw_nb15/<csv_filename>.csv
  python scripts/phase1/prepare_dataset.py register --dataset unsw_nb15 --file data/raw/unsw_nb15/<csv_filename>.csv
  ```
