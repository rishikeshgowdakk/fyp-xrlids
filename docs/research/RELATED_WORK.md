# XRL-IDARS — Related Work & Academic Grounding

**Document ID:** `DOC-RES-RELATED-WORK-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Flow-Based Network Intrusion Detection

- **Sharafaldin et al. (2018)**: Introduced the CIC-IDS2017 and CSE-CIC-IDS2018 benchmarks, demonstrating that bidirectional network flows provide sufficient statistical characteristics to detect volumetric and application-layer DoS attacks without inspecting encrypted payload contents.
- **Moustafa & Slay (2015)**: Created the UNSW-NB15 dataset using IXIA PerfectStorm toolsets to represent modern hybrid attack vectors and low-footprint reconnaissance.

---

## 2. Tree Ensembles vs. Deep Neural Networks on Tabular Data

- **Grinsztajn, Oyallon, & Varoquaux (NeurIPS 2022)**: *"Why tree-based models still outperform deep learning on tabular data"*. This landmark empirical study demonstrated that tree-based ensembles (such as Random Forest and XGBoost) consistently outperform deep architectures on tabular datasets due to their indifference to uninformative features, rotational invariance, and robustness to non-smooth decision boundaries. The findings of XRL-IDARS directly align with this conclusion.

---

## 3. Explainable AI & Feature Attribution

- **Lundberg & Lee (NeurIPS 2017)**: *"A Unified Approach to Interpreting Model Predictions"*. Established SHAP (SHapley Additive exPlanations) based on cooperative game theory, proving that Shapley values are the unique class of additive feature attributions satisfying local accuracy, missingness, and consistency.
- **Lundberg et al. (Nature Machine Intelligence 2020)**: Formulated the polynomial-time `TreeExplainer` algorithm ($O(TLD^2)$), enabling exact, real-time attribution on decision tree ensembles.

---

## 4. Safe Reinforcement Learning & Autonomous Response

- **Alshiekh et al. (AAAI 2018)**: *"Safe Reinforcement Learning via Shielding"*. Proposed placing a deterministic formal shield between an RL policy and physical actuators to prevent the exploration of unsafe state spaces. XRL-IDARS adopts this shielding design via the `DeterministicSafetyGate`.
- **Amodei et al. (2016)**: *"Concrete Problems in AI Safety"*. Highlighted negative side-effects and reward hacking in unconstrained RL systems, justifying the use of hard operational constraints and advisory/dry-run defaults.
