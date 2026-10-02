# Error Analysis Report (generated)

Status: `EMPIRICALLY OBSERVED` on test set predictions (CIC-IDS2017 Multi-File Benchmark (`EXP-P1-CIC2017-R10-001`)).

## 1. Confusion Breakdown (Random Forest @ 0.5 Threshold)

- **True Negatives (TN)**: 285,094
- **False Positives (FP - False Alarms)**: 5,951
- **False Negatives (FN - Missed Attacks)**: 640
- **True Positives (TP - Detected Attacks)**: 64,180

## 2. Confidence Distributions by Outcome

| Outcome Category | Count | Mean Predicted Score | Std Dev | Min | Median | Max |
| --- | --- | --- | --- | --- | --- | --- |
| **True Positives (TP)** | 64,180 | 0.9748 | 0.0450 | 0.5014 | 0.9896 | 1.0000 |
| **True Negatives (TN)** | 285,094 | 0.0118 | 0.0471 | 0.0000 | 0.0006 | 0.4995 |
| **False Positives (FP)** | 5,951 | 0.8649 | 0.1280 | 0.5001 | 0.9187 | 0.9992 |
| **False Negatives (FN)** | 640 | 0.3094 | 0.1154 | 0.0000 | 0.3495 | 0.4993 |

## 3. Model Disagreements and Fusion Rescues

- **Total Disagreements (RF vs LSTM)**: 8,126 (2.28%)
- **RF Predicted Attack, LSTM Predicted Benign**: 7,103
  - RF Correct: 2,297
  - RF False Alarm: 4,806
- **LSTM Predicted Attack, RF Predicted Benign**: 1,023
  - LSTM Correct: 186
  - LSTM False Alarm: 837
- **Fusion Rescues When One Model Failed**: 6,397
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0
