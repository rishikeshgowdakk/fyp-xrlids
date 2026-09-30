# Leakage Audit and Duplicate-Split Report (generated)

Status: `EMPIRICALLY OBSERVED` on real CSE-CIC-IDS2018 dataset.

## Critical Empirical Finding: Duplicate Feature Vectors

> [!WARNING]
> A naive stratified random split on the real CSE-CIC-IDS2018 file failed the leakage audit:
> - **114,315 rows (34.53%)** share identical R10 feature vectors.
> - **7,576 duplicate vectors** overlapped between Train and Validation.
> - **7,559 duplicate vectors** overlapped between Train and Test.
> - **4,357 duplicate vectors** overlapped between Validation and Test.
> This leakage leads to artificial metric inflation because the model memorizes flow vectors from training.

## Split Policies Implemented and Evaluated

| Policy | Mechanism | Leakage Overlap (L-01/L-02) | Test Evaluation Strategy | Status |
| --- | --- | --- | --- | --- |
| **Policy A** (`deduplicate_features`) | Deduplicate identical feature vectors prior to splitting | **0 vectors (Pass)** | Unbiased evaluation on unique flows | `VERIFIED` & `EMPIRICALLY OBSERVED` |
| **Policy B** (`retain_with_subset_evaluation`) | Retain all flows; split naively; tag test subsets | **7,559 vectors (Fail)** | Evaluated separately on `test_unique` vs `test_duplicate` | `VERIFIED` & `EMPIRICALLY OBSERVED` |

## Leakage Check Taxonomy

| Audit Check | Description | Status | Evidence / Result |
| --- | --- | --- | --- |
| **L-01** | Exact Duplicate Vector Overlap | `EMPIRICALLY OBSERVED` | 0 overlaps under Policy A; 7,559 overlaps under Policy B. |
| **L-02** | Near-Duplicate Vector Overlap | `EMPIRICALLY OBSERVED` | 0 overlaps under Policy A (atol=1e-5). |
| **L-03** | Temporal Boundary Overlap | `NOT_PERFORMED` | Exact monotonic millisecond timestamps not present in single CSV extract. |
| **L-04** | Source IP / Group Contamination | `NOT_PERFORMED` | Source IP addresses stripped in anonymized public dataset. |
| **L-05** | Label Contamination | `VERIFIED` | Labels strictly isolated; no label leakage into features. |
| **L-06** | Preprocessing Contamination | `VERIFIED` | Scaler and imputer fitted on Train only; transform-only on Val/Test. |
