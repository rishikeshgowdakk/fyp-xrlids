# XRL-IDARS Detector-to-DQN Integration Benchmark Report

| Pairing Configuration | Detector | Architecture | Median Latency (ms) | Mean Cost/Flow | Containment Rate | Availability | Throughput (fps) |
|---|:---:|:---:|---:|---:|---:|---:|---:|
| **Pairing_1_Binary_RF_Binary_DQN** | RandomForestDetector | Binary (6D) | 38.916 ms | 5.7126 | 98.47% | 70.85% | 2261.2 |
| **Pairing_2_Binary_XGBoost_Binary_DQN** | XGBoostDetector | Binary (6D) | 0.802 ms | 5.7126 | 98.47% | 70.85% | 3418.8 |
| **Pairing_3_Attack_Aware_RF_Attack_Aware_DQN** | RandomForestDetector | Attack-Aware (8D) | 85.659 ms | 13.1803 | 39.93% | 74.05% | 1505.9 |
| **Pairing_4_Attack_Aware_XGBoost_Attack_Aware_DQN** | XGBoostDetector | Attack-Aware (8D) | 62.858 ms | 13.1803 | 39.93% | 74.05% | 1726.4 |
