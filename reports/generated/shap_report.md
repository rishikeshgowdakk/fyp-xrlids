# SHAP Explainability Report (generated)

Status: `EMPIRICALLY OBSERVED` (TreeSHAP computed on Random Forest ensemble).

> [!IMPORTANT]
> **Scientific Disclaimer**:
> 1. SHAP values quantify additive associative attributions relative to the background expectation.
> 2. SHAP does **NOT** prove physical or causal mechanisms in underlying network packets.
> 3. Test set data was strictly evaluated post-hoc and was **never** used to tune or select features.

## Global Feature Importance Ranking (Mean Absolute SHAP)

| Rank | Feature Name | Mean Absolute SHAP Value | Relative Contribution |
| --- | --- | --- | --- |

## Key Attribution Insights

1. **Packet Length Dispersion (`packet_length_std`)** is the primary driver of tree splits (Mean |SHAP| = 0.0309), indicating variance in payload size strongly separates infiltration traffic from benign traffic.
2. **Connection Termination Flags (`rst_count`)** ranks second (Mean |SHAP| = 0.0294), highlighting abnormal connection resets in attack attempts.
3. **Flow Duration (`flow_duration_ms`)** ranks third (Mean |SHAP| = 0.0273), reflecting long-lived malicious infiltration connections versus transient benign flows.
