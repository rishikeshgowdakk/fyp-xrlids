# XRL-IDARS — Data Preprocessing & Leakage Prevention Policy

**Document ID:** `DOC-ML-PREPROC-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Zero Target Leakage Policy

To guarantee the academic defense of the system, XRL-IDARS enforces a strict **Zero Data Leakage Invariant**:
1. **Fit Strictly on Train**: All statistical scaling parameters (mean $\mu$, variance $\sigma^2$) are fitted exclusively on the training partition ($D_{\text{train}}$).
2. **Transform Only on Test & Inference**: Validation sets, test sets, and live packet streams execute `.transform()` without mutating scaling parameters.
3. **Artifact Serialization**: Fitted preprocessors are serialized as frozen `preprocessor.joblib` artifacts alongside the model checkpoints.

---

## 2. Preprocessing Pipeline Architecture

```
Raw Feature Dict (10 Floats)
         |
         v
[Schema & Type Validator]   --> Reject NaN, Inf, missing keys, string types
         |
         v
[Ordered DataFrame / Array] --> Align to canonical R10 column order
         |
         v
[StandardScaler Transform]  --> x_scaled = (x - mu) / sigma
         |
         v
[Model Ready Tensor/Array]  --> float32 NumPy array passed to RF / LSTM
```

---

## 3. Robust Handling of Numerical Edge Cases

- **Infinite Values (`Inf`, `-Inf`)**: Arise when duration is zero ($d_s = 0$). Handled by imposing a floor on duration:
  $$d_{\text{effective}} = \max(d_s, 0.001\,\text{s})$$
- **Not-a-Number (`NaN`)**: Arise from empty packet length arrays. Handled by defaulting mean and standard deviation to $0.0$.
- **Division by Zero in SYN/ACK Ratio**: Handled via Laplace additive smoothing:
  $$\text{syn\_ack\_ratio} = \frac{N_{\text{syn}} + 1.0}{N_{\text{ack}} + 1.0}$$
