# XRL-IDARS — TreeSHAP Explainability Specification

**Module:** `src/xrlids/explainability/explainer.py` (`TreeSHAPExplainer`)  
**Theoretical Basis:** Lundberg & Lee, *A Unified Approach to Interpreting Model Predictions*, NeurIPS 2017.

---

## 1. Principles & Local Additive Attribution

Explainable AI in XRL-IDARS provides deterministic, mathematically grounded local feature attributions for every classified flow along the primary ML detection path (Random Forest and XGBoost).

For a given flow feature vector $\mathbf{x} = (x_1, x_2, \dots, x_M)$, TreeSHAP assigns an attribution value $\phi_i \in \mathbb{R}$ to each feature $i \in \{1, \dots, M\}$ such that:

$$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^M \phi_i(\mathbf{x})$$

Where:
- $f(\mathbf{x})$ is the model's prediction score (or log-odds margin).
- $\phi_0 = \mathbb{E}[f(\mathbf{x})]$ is the expected baseline value (base value) across the training distribution.
- $\phi_i(\mathbf{x})$ is the local Shapley value of feature $i$, reflecting its exact additive contribution to the prediction.

---

## 2. Directionality & Semantic Interpretation

In the XRL-IDARS detection engine:
- $\phi_i > 0$ (**`INCREASES_THREAT`**): The observed value of feature $i$ pushes the model prediction towards the **ATTACK** class.
  - *Example:* A high `syn_ack_ratio` (e.g. 10.0) indicates disproportionate SYN packets characteristic of a SYN Flood, generating a positive Shapley value.
- $\phi_i < 0$ (**`DECREASES_THREAT`**): The observed value of feature $i$ pushes the model prediction towards the **BENIGN** class.
  - *Example:* A balanced packet exchange (`syn_ack_ratio \approx 0.5`) and standard packet length distribution provides evidence of legitimate TCP communications.
- $\phi_i \approx 0$ (**`NEUTRAL`**): Feature has negligible effect on the prediction decision.

Features are ranked in descending order of absolute importance $|\phi_i|$ to surface the primary explanatory drivers to security operators.

---

## 3. Supported Model Architectures

The unified `TreeSHAPExplainer` supports:

1. **Random Forest Champion (`RandomForestClassifier`):**
   - Evaluates tree ensemble paths using tree conditional expectations.
   - Attributions computed directly on posterior attack probability $P(\text{class} = 1)$.
2. **XGBoost Candidate (`XGBClassifier`):**
   - Tree paths traversed with leaf margin weights.
   - Additive contributions in log-odds space with monotonic sigmoid mapping to threat probability.

---

## 4. Separation from RL Policy Explanation

TreeSHAP explanations strictly explain **why the primary ML detector classified a flow as an attack**.

They do **not** explain the reinforcement learning response policy. The DQN response decision is independently explained by its 6D state representation $\mathbf{s}_t$, action candidate Q-values $Q(\mathbf{s}_t, a)$, and safety gate constraints. Conflating TreeSHAP with RL action selection is mathematically invalid and prohibited by the architecture.
