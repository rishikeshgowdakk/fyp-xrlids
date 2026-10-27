# Limitations and Threats to Validity — Phase 2A Controlled Benchmark

1. **Exogenous Flow Generation**:
   The response simulation operates by replaying pre-recorded flow sequences from CSE-CIC-IDS2017.
   The agent's mitigation actions (RATE_LIMIT, ISOLATE) do not alter future traffic generation,
   packet arrival times, or adversarial strategy. The problem is fundamentally an Asymmetric-Loss
   Contextual Bandit with Hysteresis Constraints, not a sequential MDP with causal environmental feedback.

2. **Probability Miscalibration**:
   Detector risk scores $S_t$ from the frozen Random Forest detector are uncalibrated voting fractions.
   In intermediate bins ($S_t \in [0.1, 0.3]$), predicted scores exceed observed empirical attack frequencies
   by up to an order of magnitude. Therefore, threshold derivations are cost-optimal with respect to the
   assumed score, not mathematically proven Bayes-optimal on true posterior probabilities.

3. **Research Cost Assumptions**:
   Scalar penalties in `ResearchCostEngine` ($C(a, y)$, chattering penalty 10.0, fatigue slope 0.5)
   are explicit academic assumptions designed to induce controlled asymmetric loss gradients.
   They do not represent site-specific enterprise financial accounting.

4. **Safety Gate Dominance in 4-Action Space**:
   In 4-action mode, the deterministic 5% blast radius circuit breaker intercepts thousands of high-confidence
   isolation proposals, downgrading them to ALERT. The safety gate acts as an external regularizer that
   heavily constrains extreme policy behaviors.
