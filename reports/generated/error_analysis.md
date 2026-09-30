# Error Analysis Report (generated)

Status: `EMPIRICALLY OBSERVED` on test set predictions.

## 1. Confusion Breakdown (Random Forest @ 0.5 Threshold)

- **True Negatives (TN)**: 23,352
- **False Positives (FP - False Alarms)**: 10,018
- **False Negatives (FN - Missed Attacks)**: 5,242
- **True Positives (TP - Detected Attacks)**: 4,728

## 2. Confidence Distributions by Outcome

| Outcome Category | Count | Mean Predicted Score | Std Dev | Min | Median | Max |
| --- | --- | --- | --- | --- | --- | --- |
| **True Positives (TP)** | 4,728 | 0.6343 | 0.1670 | 0.5000 | 0.5409 | 0.9981 |
| **True Negatives (TN)** | 23,352 | 0.3706 | 0.1337 | 0.0010 | 0.4235 | 0.5000 |
| **False Positives (FP)** | 10,018 | 0.5436 | 0.0629 | 0.5000 | 0.5237 | 0.9958 |
| **False Negatives (FN)** | 5,242 | 0.4186 | 0.0929 | 0.0164 | 0.4557 | 0.5000 |

## 3. Model Disagreements and Fusion Rescues

- **Total Disagreements (RF vs LSTM)**: 14,287 (0.00%)
- **RF Predicted Attack, LSTM Predicted Benign**: 0
  - RF Correct: 0
  - RF False Alarm: 0
- **LSTM Predicted Attack, RF Predicted Benign**: 0
  - LSTM Correct: 0
  - LSTM False Alarm: 0
- **Fusion Rescues When One Model Failed**: 0
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0
